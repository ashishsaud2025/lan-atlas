package org.lanmanager.prototype;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.util.JsonReader;
import android.util.JsonToken;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.Base64;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Foreground-only Android network observatory with UDP discovery and framed ECHO. */
public class MainActivity extends Activity {
    private static final String TAG = "LANManager";
    private static final String THEME_PREFERENCES = "lan_atlas_ui";
    private static final String THEME_KEY = "theme";
    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int PAGE_OVERVIEW = 0;
    private static final int PAGE_NETWORK = 1;
    private static final int PAGE_DEVICES = 2;
    private static final int PAGE_WORKBENCH = 3;
    private static final int PAGE_CHAT = 4;
    private static final int PAGE_MORE = 5;
    private static final int REQUEST_OPEN_FILE = 100;
    private static final int REQUEST_CREATE_FILE = 101;
    private static final int VERIFY_TIMEOUT_MS = 300000;

    private EditText name_input;
    private EditText host_input;
    private TextView top_session_summary;
    private TextView top_nearby;
    private TextView session_state;
    private TextView nearby_metric;
    private TextView discovery_metric;
    private TextView echo_metric;
    private TextView selected_target;
    private TextView probe_status;
    private TextView log_view;
    private TextView peer_id_view;
    private TextView session_id_view;
    private TextView empty_devices;
    private TextView device_limit_note;
    private TextView transfer_status;
    private TextView chat_peer_label;
    private TextView chat_history;
    private EditText chat_input;
    private Button chat_scope_room;
    private Button chat_scope_dm;
    private Button chat_send;
    private boolean chat_dm;
    private LinearLayout device_list;
    private ObservedTopologyView topology_view;
    private ProgressBar transfer_progress;
    private Button probe_button;
    private Button send_file_button;
    private Button accept_file_button;
    private Button decline_file_button;
    private Button cancel_transfer_button;
    private View[] pages;
    private Button[] navigation;
    private final StringBuilder log_buffer = new StringBuilder();
    private String peer_id;
    private String selected_host;
    private int selected_port = 50002;
    private PeerSnapshot selected_peer;
    private PeerSnapshot pending_send_peer;
    private int selected_page = PAGE_OVERVIEW;
    private boolean picker_active;
    private int picker_generation;
    private Runnable picker_timeout;
    private final Handler main_handler = new Handler(Looper.getMainLooper());
    private volatile Session current;

    private static final class TransferTask {
        final String id;
        final boolean incoming;
        final CountDownLatch decision = new CountDownLatch(1);
        final CancellationSignal provider_signal = new CancellationSignal();
        volatile Socket socket;
        volatile Closeable provider_io;
        volatile boolean cancelled;
        volatile boolean declined;
        volatile Uri destination;
        String name;
        long size;
        String digest;
        String remote_peer_id;
        String remote_session_id;

        TransferTask(String id, boolean incoming) {
            this.id = id;
            this.incoming = incoming;
        }
    }

    private static final class HashResult {
        final long size;
        final String digest;

        HashResult(long size, String digest) {
            this.size = size;
            this.digest = digest;
        }
    }

    private static final class Session {
        final String id = UUID.randomUUID().toString();
        volatile boolean running = true;
        volatile boolean discovery_active;
        volatile boolean echo_active;
        volatile boolean chat_active;
        volatile DatagramSocket udp;
        volatile ServerSocket listener;
        volatile ServerSocket chat_listener;
        volatile TransferTask transfer;
        volatile List<PeerSnapshot> roster = Collections.emptyList();
        final ChatRules.ChatDedupe chat_seen = new ChatRules.ChatDedupe();
        final List<ChatEntry> chat_history =
            Collections.synchronizedList(new ArrayList<>());
        WifiManager.MulticastLock wifi_lock;
        final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        final ThreadPoolExecutor workers = new ThreadPoolExecutor(
            8, 8, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8));
    }

    private static final class ChatEntry {
        final String id = UUID.randomUUID().toString();
        final String direction;
        final String scope;
        final String text;
        final String sender;
        volatile String state;

        ChatEntry(String direction, String scope, String text, String sender, String state) {
            this.direction = direction;
            this.scope = scope;
            this.text = text;
            this.sender = sender;
            this.state = state;
        }
    }

    @Override public void onCreate(Bundle saved_state) {
        String theme = getSharedPreferences(THEME_PREFERENCES, MODE_PRIVATE)
            .getString(THEME_KEY, "observatory");
        setTheme("atlas".equals(theme)
            ? R.style.Theme_LanAtlas_Atlas : R.style.Theme_LanAtlas_Observatory);
        super.onCreate(saved_state);
        setContentView(R.layout.activity_main);
        peer_id = getPreferences(MODE_PRIVATE).getString("peer_id", null);
        if (peer_id == null) {
            peer_id = UUID.randomUUID().toString();
            getPreferences(MODE_PRIVATE).edit().putString("peer_id", peer_id).apply();
        }
        bind_views();
        setup_navigation();
        findViewById(R.id.start_button).setOnClickListener(view -> start_session());
        findViewById(R.id.stop_button).setOnClickListener(view -> stop_session());
        probe_button.setOnClickListener(view -> probe());
        chat_scope_room.setOnClickListener(view -> choose_chat_scope(false));
        chat_scope_dm.setOnClickListener(view -> choose_chat_scope(true));
        chat_send.setOnClickListener(view -> send_chat_from_composer());
        send_file_button.setOnClickListener(view -> choose_file_to_send());
        accept_file_button.setOnClickListener(view -> accept_incoming_file());
        decline_file_button.setOnClickListener(view -> decline_incoming_file());
        cancel_transfer_button.setOnClickListener(view -> cancel_transfer());
        findViewById(R.id.theme_dark).setOnClickListener(view -> choose_theme("observatory"));
        findViewById(R.id.theme_light).setOnClickListener(view -> choose_theme("atlas"));
        topology_view.set_listener(this::select_target);
        peer_id_view.setText(peer_id);
        if (saved_state != null) selected_page = saved_state.getInt("page", PAGE_OVERVIEW);
        show_page(selected_page);
        update_session_ui(null);
        update_roster_ui(null, Collections.emptyList());
    }

    private void bind_views() {
        name_input = findViewById(R.id.name_input);
        host_input = findViewById(R.id.host_input);
        top_session_summary = findViewById(R.id.top_session_summary);
        top_nearby = findViewById(R.id.top_nearby);
        session_state = findViewById(R.id.session_state);
        nearby_metric = findViewById(R.id.nearby_metric);
        discovery_metric = findViewById(R.id.discovery_metric);
        echo_metric = findViewById(R.id.echo_metric);
        selected_target = findViewById(R.id.selected_target);
        probe_status = findViewById(R.id.probe_status);
        log_view = findViewById(R.id.log_view);
        peer_id_view = findViewById(R.id.peer_id_view);
        session_id_view = findViewById(R.id.session_id_view);
        empty_devices = findViewById(R.id.empty_devices);
        device_limit_note = findViewById(R.id.device_limit_note);
        transfer_status = findViewById(R.id.transfer_status);
        chat_peer_label = findViewById(R.id.chat_peer_label);
        chat_history = findViewById(R.id.chat_history);
        chat_input = findViewById(R.id.chat_input);
        chat_scope_room = findViewById(R.id.chat_scope_room);
        chat_scope_dm = findViewById(R.id.chat_scope_dm);
        chat_send = findViewById(R.id.chat_send);
        device_list = findViewById(R.id.device_list);
        topology_view = findViewById(R.id.topology_view);
        transfer_progress = findViewById(R.id.transfer_progress);
        probe_button = findViewById(R.id.probe_button);
        send_file_button = findViewById(R.id.send_file_button);
        accept_file_button = findViewById(R.id.accept_file_button);
        decline_file_button = findViewById(R.id.decline_file_button);
        cancel_transfer_button = findViewById(R.id.cancel_transfer_button);
        pages = new View[]{findViewById(R.id.page_overview), findViewById(R.id.page_network),
            findViewById(R.id.page_devices), findViewById(R.id.page_workbench),
            findViewById(R.id.page_chat), findViewById(R.id.page_more)};
        navigation = new Button[]{findViewById(R.id.nav_overview),
            findViewById(R.id.nav_network), findViewById(R.id.nav_devices),
            findViewById(R.id.nav_workbench), findViewById(R.id.nav_chat),
            findViewById(R.id.nav_more)};
    }

    private void setup_navigation() {
        for (int index = 0; index < navigation.length; index++) {
            int page = index;
            navigation[index].setOnClickListener(view -> show_page(page));
        }
    }

    private void show_page(int page) {
        if (page < 0 || page >= pages.length) return;
        selected_page = page;
        for (int index = 0; index < pages.length; index++) {
            pages[index].setVisibility(index == page ? View.VISIBLE : View.GONE);
            navigation[index].setSelected(index == page);
        }
    }

    private void choose_theme(String theme) {
        getSharedPreferences(THEME_PREFERENCES, MODE_PRIVATE)
            .edit().putString(THEME_KEY, theme).apply();
        recreate();
    }

    private void report(Session session, String text) {
        Log.i(TAG, text);
        runOnUiThread(() -> {
            if (session != null && current != session) return;
            log_buffer.append(LocalTime.now().format(LOG_TIME)).append("  ")
                .append(text).append('\n');
            if (log_buffer.length() > 12000) {
                log_buffer.delete(0, log_buffer.length() - 8000);
            }
            log_view.setText(log_buffer.toString());
        });
    }

    private void start_session() {
        stop_session();
        String name = name_input.getText().toString().trim();
        if (!DiscoveryRules.valid_name(name)) {
            name_input.setError(getString(R.string.name_error));
            report(null, getString(R.string.name_error));
            return;
        }
        name_input.setError(null);
        Session session = new Session();
        current = session;
        WifiManager manager = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        if (manager != null) {
            session.wifi_lock = manager.createMulticastLock("lan-manager-test");
            session.wifi_lock.setReferenceCounted(false);
            session.wifi_lock.acquire();
        }
        update_session_ui(session);
        report(session, getString(R.string.started_session, short_id(session.id)));
        session.workers.execute(() -> discovery(session, name));
        session.workers.execute(() -> echo_server(session));
        session.workers.execute(() -> chat_server(session));
    }

    private void stop_session() {
        Session session = current;
        if (session == null) return;
        current = null;
        synchronized (session) {
            session.running = false;
            if (session.transfer != null) {
                session.transfer.cancelled = true;
                session.transfer.provider_signal.cancel();
                close_provider_io(session.transfer);
                session.transfer.decision.countDown();
            }
            if (session.udp != null) session.udp.close();
            try {
                if (session.listener != null) session.listener.close();
            } catch (IOException error) {
                Log.d(TAG, "Listener close", error);
            }
            try {
                if (session.chat_listener != null) session.chat_listener.close();
            } catch (IOException error) {
                Log.d(TAG, "Chat listener close", error);
            }
        }
        for (Socket socket : session.sockets) {
            try {
                socket.close();
            } catch (IOException error) {
                Log.d(TAG, "Socket close", error);
            }
        }
        session.workers.shutdownNow();
        if (session.wifi_lock != null && session.wifi_lock.isHeld()) {
            session.wifi_lock.release();
        }
        update_session_ui(null);
        update_roster_ui(null, Collections.emptyList());
        update_transfer_ui(null, getString(R.string.transfer_idle), 0, false);
        report(null, getString(R.string.networking_stopped));
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putInt("page", selected_page);
        super.onSaveInstanceState(state);
    }

    @Override protected void onStop() {
        if (!picker_active) stop_session();
        super.onStop();
    }

    @Override protected void onDestroy() {
        picker_active = false;
        picker_generation++;
        if (picker_timeout != null) main_handler.removeCallbacks(picker_timeout);
        picker_timeout = null;
        stop_session();
        super.onDestroy();
    }

    private void update_session_ui(Session session) {
        runOnUiThread(() -> {
            if (session != null && current != session) return;
            if (session == null && current != null) return;
            boolean running = session != null && current == session && session.running;
            session_state.setText(running ? R.string.running : R.string.stopped);
            top_session_summary.setText(running
                ? getString(R.string.started_session, short_id(session.id))
                : getString(R.string.foreground_only));
            discovery_metric.setText(running && session.discovery_active
                ? R.string.active : R.string.inactive);
            echo_metric.setText(running && (session.echo_active || session.chat_active)
                ? R.string.listening_port : R.string.inactive);
            session_id_view.setText(running ? session.id : getString(R.string.no_active_session));
        });
    }

    private void discovery(Session session, String name) {
        Map<String, PeerSnapshot> peers = new HashMap<>();
        if (!session.running) return;
        try (DatagramSocket socket = new DatagramSocket(null)) {
            synchronized (session) {
                if (!session.running) return;
                session.udp = socket;
            }
            socket.setReuseAddress(true);
            socket.setBroadcast(true);
            socket.bind(new InetSocketAddress("0.0.0.0", 50000));
            socket.setSoTimeout(250);
            session.discovery_active = true;
            update_session_ui(session);
            JSONObject hello = new JSONObject().put("version", 1).put("peer_id", peer_id)
                .put("session_id", session.id).put("name", name).put("tcp_port", ChatRules.CHAT_PORT)
                .put("capabilities", new JSONArray().put("echo_v1").put("file_v1").put("chat_v1"));
            byte[] packet = ("LMAN\u0001" + hello).getBytes(StandardCharsets.UTF_8);
            if (packet.length > 1200) throw new IOException("HELLO too large");
            long next_announcement = 0;
            long next_ui = 0;
            byte[] receive_buffer = new byte[65535];
            while (session.running) {
                long now = SystemClock.elapsedRealtime();
                if (now >= next_announcement) {
                    socket.send(new DatagramPacket(packet, packet.length,
                        InetAddress.getByName("255.255.255.255"), 50000));
                    next_announcement = now + 2000;
                }
                long cutoff = now - 6000;
                peers.entrySet().removeIf(entry -> entry.getValue().last_seen_ms <= cutoff);
                DatagramPacket incoming = new DatagramPacket(receive_buffer, receive_buffer.length);
                try {
                    socket.receive(incoming);
                } catch (SocketTimeoutException ignored) {
                    // Receive silence must still allow announcement and expiry checks.
                    incoming = null;
                }
                if (incoming != null) {
                    try {
                        PeerSnapshot peer = decode_hello(incoming, session.id);
                        if (peer != null
                                && (peers.containsKey(peer.session_id) || peers.size() < 256)) {
                            peers.put(peer.session_id, peer);
                        }
                    } catch (JSONException | IllegalArgumentException | IOException error) {
                        Log.w(TAG, "Malformed HELLO", error);
                    }
                }
                now = SystemClock.elapsedRealtime();
                if (now >= next_ui) {
                    List<PeerSnapshot> snapshot = new ArrayList<>(peers.values());
                    snapshot.sort(Comparator.comparing(peer -> peer.name));
                    update_roster_ui(session, snapshot);
                    next_ui = now + 2000;
                }
            }
        } catch (Exception error) {
            if (session.running) {
                report(session, getString(R.string.discovery_stopped, error));
            }
        } finally {
            session.discovery_active = false;
            update_session_ui(session);
        }
    }

    private PeerSnapshot decode_hello(DatagramPacket incoming, String local_session)
            throws IOException, JSONException {
        int size = incoming.getLength();
        byte[] data = incoming.getData();
        if (size < 6 || size > 1200 || data[0] != 'L' || data[1] != 'M'
                || data[2] != 'A' || data[3] != 'N' || data[4] != 1) return null;
        JSONObject other = parse(decode_utf8(data, 5, size - 5));
        if (!Integer.valueOf(1).equals(other.get("version"))) return null;
        String session_id = DiscoveryRules.canonical_uuid(other.getString("session_id"));
        String remote_peer_id = DiscoveryRules.canonical_uuid(other.getString("peer_id"));
        if (session_id.equals(local_session)) return null;
        int port = other.getInt("tcp_port");
        if (port < 1 || port > 65535) return null;
        String name = other.getString("name");
        if (!DiscoveryRules.valid_name(name)) return null;
        JSONArray raw_capabilities = other.getJSONArray("capabilities");
        if (raw_capabilities.length() > 16) return null;
        List<String> capabilities = new ArrayList<>();
        for (int index = 0; index < raw_capabilities.length(); index++) {
            Object item = raw_capabilities.get(index);
            if (!(item instanceof String)
                    || !DiscoveryRules.valid_capability((String) item)) return null;
            capabilities.add((String) item);
        }
        return new PeerSnapshot(remote_peer_id, session_id, name,
            incoming.getAddress().getHostAddress(), port, capabilities,
            SystemClock.elapsedRealtime());
    }

    private void update_roster_ui(Session session, List<PeerSnapshot> peers) {
        runOnUiThread(() -> {
            if (session != null && current != session) return;
            if (session == null && current != null) return;
            if (session != null) {
                session.roster = Collections.unmodifiableList(new ArrayList<>(peers));
            }
            int count = peers.size();
            top_nearby.setText(getResources().getQuantityString(
                R.plurals.sessions_nearby, count, count));
            nearby_metric.setText(String.valueOf(count));
            empty_devices.setVisibility(peers.isEmpty() ? View.VISIBLE : View.GONE);
            device_list.removeAllViews();
            LayoutInflater inflater = LayoutInflater.from(this);
            int visible_count = Math.min(peers.size(), 64);
            for (int index = 0; index < visible_count; index++) {
                PeerSnapshot peer = peers.get(index);
                View item = inflater.inflate(R.layout.item_device, device_list, false);
                TextView name = item.findViewById(R.id.device_name);
                TextView endpoint = item.findViewById(R.id.device_endpoint);
                TextView state = item.findViewById(R.id.device_state);
                TextView capabilities = item.findViewById(R.id.device_capabilities);
                TextView identity = item.findViewById(R.id.device_identity);
                Button workbench = item.findViewById(R.id.device_workbench);
                double age = Math.max(0, SystemClock.elapsedRealtime() - peer.last_seen_ms) / 1000.0;
                name.setText(peer.name);
                endpoint.setText(getString(R.string.endpoint_format, peer.ip, peer.tcp_port));
                state.setText(getString(R.string.nearby_state, age));
                capabilities.setText(getString(R.string.capabilities_format,
                    String.join(" · ", peer.capabilities)));
                identity.setText(getString(R.string.device_identity_format,
                    short_id(peer.peer_id), short_id(peer.session_id)));
                boolean actionable = peer.has_capability("echo_v1")
                    || peer.has_capability("file_v1");
                workbench.setEnabled(actionable);
                workbench.setOnClickListener(view -> select_target(peer));
                if (actionable) {
                    item.setOnClickListener(view -> select_target(peer));
                }
                item.setContentDescription(name.getText() + ", " + endpoint.getText()
                    + ", " + state.getText());
                device_list.addView(item);
            }
            device_limit_note.setVisibility(peers.size() > visible_count
                ? View.VISIBLE : View.GONE);
            if (peers.size() > visible_count) {
                device_limit_note.setText(getResources().getQuantityString(
                    R.plurals.showing_devices, peers.size(), visible_count, peers.size()));
            }
            topology_view.set_peers(name_input.getText().toString(),
                peers.subList(0, Math.min(peers.size(), 12)));
            if (selected_peer != null) {
                PeerSnapshot refreshed = null;
                for (PeerSnapshot peer : peers) {
                    if (peer.session_id.equals(selected_peer.session_id)) {
                        refreshed = peer;
                        break;
                    }
                }
                if (refreshed == null) {
                    selected_peer = null;
                    send_file_button.setEnabled(false);
                    probe_button.setEnabled(false);
                    selected_target.setText(R.string.no_selected_device);
                } else {
                    selected_peer = refreshed;
                    selected_host = refreshed.ip;
                    selected_port = refreshed.tcp_port;
                    host_input.setText(refreshed.ip);
                    probe_button.setEnabled(refreshed.has_capability("echo_v1"));
                    send_file_button.setEnabled(session != null && session.transfer == null
                        && refreshed.has_capability("file_v1"));
                    selected_target.setText(getString(R.string.selected_target_format,
                        refreshed.name, refreshed.ip, refreshed.tcp_port));
                }
            }
            update_chat_ui(session);
        });
    }

    private void select_target(PeerSnapshot peer) {
        host_input.setText(peer.ip);
        selected_host = peer.ip;
        selected_port = peer.tcp_port;
        selected_peer = peer;
        probe_button.setEnabled(peer.has_capability("echo_v1"));
        send_file_button.setEnabled(peer.has_capability("file_v1"));
        selected_target.setText(getString(R.string.selected_target_format,
            peer.name, peer.ip, peer.tcp_port));
        update_chat_ui(current);
        show_page(PAGE_WORKBENCH);
    }

    private JSONObject message(Session session, String type, JSONObject body) throws JSONException {
        return new JSONObject().put("version", 1).put("type", type)
            .put("message_id", UUID.randomUUID().toString()).put("peer_id", peer_id)
            .put("session_id", session.id).put("body", body);
    }

    private JSONObject receive(Socket socket) throws Exception {
        return receive(socket, 5000);
    }

    private JSONObject receive(Socket socket, int timeout_ms) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + timeout_ms;
        InputStream stream = new FilterInputStream(socket.getInputStream()) {
            @Override public int read(byte[] bytes, int offset, int size) throws IOException {
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) throw new SocketTimeoutException("Frame deadline");
                socket.setSoTimeout((int) remaining);
                return in.read(bytes, offset, size);
            }
        };
        String json = Frames.receive(stream);
        if (json == null) return null;
        JSONObject value = parse(json);
        if (!Integer.valueOf(1).equals(value.get("version"))) {
            throw new IOException("Unsupported version");
        }
        for (String key : new String[]{"peer_id", "session_id", "message_id"}) {
            DiscoveryRules.canonical_uuid(value.getString(key));
        }
        value.getJSONObject("body");
        return value;
    }

    private void echo_server(Session session) {
        if (!session.running) return;
        try (ServerSocket listener = new ServerSocket()) {
            synchronized (session) {
                if (!session.running) return;
                session.listener = listener;
            }
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress("0.0.0.0", 50002));
            listener.setSoTimeout(250);
            session.echo_active = true;
            update_session_ui(session);
            report(session, getString(R.string.listening_port));
            while (session.running) {
                Socket socket;
                try {
                    socket = listener.accept();
                } catch (SocketTimeoutException ignored) {
                    continue;
                }
                session.sockets.add(socket);
                try {
                    session.workers.execute(() -> handle_connection(
                        session, socket, ChatRules.ECHO_PORT));
                } catch (RejectedExecutionException error) {
                    session.sockets.remove(socket);
                    try {
                        socket.close();
                    } catch (IOException close_error) {
                        Log.d(TAG, "Rejected connection close", close_error);
                    }
                }
            }
        } catch (Exception error) {
            if (session.running) report(session, getString(R.string.echo_stopped, error));
        } finally {
            session.echo_active = false;
            update_session_ui(session);
        }
    }

    private void chat_server(Session session) {
        if (!session.running) return;
        try (ServerSocket listener = new ServerSocket()) {
            synchronized (session) {
                if (!session.running) return;
                session.chat_listener = listener;
            }
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress("0.0.0.0", ChatRules.CHAT_PORT));
            listener.setSoTimeout(250);
            session.chat_active = true;
            update_session_ui(session);
            while (session.running) {
                Socket socket;
                try {
                    socket = listener.accept();
                } catch (SocketTimeoutException ignored) {
                    continue;
                }
                session.sockets.add(socket);
                try {
                    session.workers.execute(() -> handle_connection(
                        session, socket, ChatRules.CHAT_PORT));
                } catch (RejectedExecutionException error) {
                    session.sockets.remove(socket);
                    try {
                        socket.close();
                    } catch (IOException close_error) {
                        Log.d(TAG, "Rejected connection close", close_error);
                    }
                }
            }
        } catch (Exception error) {
            if (session.running) report(session, getString(R.string.chat_stopped, error));
        } finally {
            session.chat_active = false;
            update_session_ui(session);
        }
    }

    private void handle_connection(Session session, Socket socket, int port) {
        try (socket) {
            JSONObject request = receive(socket);
            if (request == null) return;
            if ("FILE_OFFER".equals(request.getString("type"))) {
                receive_file(session, socket, request);
                return;
            }
            if ("CHAT".equals(request.getString("type"))) {
                if (!ChatRules.acceptsChat(port)) throw new IOException("CHAT needs the chat port");
                receive_chat(session, socket, request);
                return;
            }
            while (session.running) {
                if (!"ECHO".equals(request.getString("type"))) {
                    throw new IOException("Expected ECHO or FILE_OFFER");
                }
                JSONObject reply = message(
                    session, "ECHO_REPLY", request.getJSONObject("body"));
                reply.put("reply_to", request.getString("message_id"));
                Frames.send(socket.getOutputStream(), reply.toString());
                request = receive(socket);
                if (request == null) return;
            }
        } catch (Exception error) {
            if (session.running) {
                report(session, getString(R.string.connection_ended, error));
            }
        } finally {
            session.sockets.remove(socket);
        }
    }

    private void receive_chat(Session session, Socket socket, JSONObject request) throws Exception {
        JSONObject body = request.getJSONObject("body");
        String scope = body.getString("scope");
        if (!"room".equals(scope) && !"dm".equals(scope)) {
            throw new IOException("Invalid chat scope");
        }
        String text = body.getString("text");
        if (!ChatRules.validIncomingText(text)) throw new IOException("Invalid chat text");
        if ("dm".equals(scope)
                && !ChatRules.acceptableDm(body.getString("to_session"), session.id)) {
            throw new IOException("DM addressed to another session");
        }
        String sender_session = request.getString("session_id");
        String sender_peer = request.getString("peer_id");
        boolean fresh = session.chat_seen.fresh(sender_session, request.getString("message_id"));
        if (fresh) {
            String sender = sender_peer.substring(0, 8);
            for (PeerSnapshot peer : session.roster) {
                if (peer.peer_id.equals(sender_peer)) {
                    sender = peer.name;
                    break;
                }
            }
            synchronized (session.chat_history) {
                session.chat_history.add(new ChatEntry(
                    "in", scope, text, sender + " (unverified)", "accepted"));
                while (session.chat_history.size() > ChatRules.MAX_HISTORY) {
                    session.chat_history.remove(0);
                }
            }
            report(session, "Chat " + scope + " from " + sender);
        }
        update_chat_ui(session);
        JSONObject reply = message(session, "ACK", new JSONObject().put("status", "accepted"));
        reply.put("reply_to", request.getString("message_id"));
        Frames.send(socket.getOutputStream(), reply.toString());
    }

    private void send_chat(PeerSnapshot peer, String scope, String text) {
        Session session = current;
        if (session == null || !session.running || peer == null
                || !peer.has_capability("chat_v1")) {
            return;
        }
        String clean;
        try {
            clean = ChatRules.requireText(text);
        } catch (IllegalArgumentException error) {
            report(session, getString(R.string.chat_invalid_text));
            return;
        }
        ChatEntry entry = new ChatEntry("out", scope, clean,
            getString(R.string.this_device), "queued");
        synchronized (session.chat_history) {
            session.chat_history.add(entry);
            while (session.chat_history.size() > ChatRules.MAX_HISTORY) {
                session.chat_history.remove(0);
            }
        }
        update_chat_ui(session);
        try {
            session.workers.execute(() -> deliver_chat(session, entry, peer, scope, clean));
        } catch (RejectedExecutionException error) {
            entry.state = "failed";
            update_chat_ui(session);
        }
    }

    private void deliver_chat(Session session, ChatEntry entry, PeerSnapshot peer,
                              String scope, String text) {
        try (Socket socket = new Socket()) {
            session.sockets.add(socket);
            try {
                socket.connect(new InetSocketAddress(peer.ip, peer.tcp_port), 3000);
                JSONObject body = new JSONObject()
                    .put("scope", scope).put("text", text);
                if ("dm".equals(scope)) body.put("to_session", peer.session_id);
                JSONObject request = message(session, "CHAT", body);
                Frames.send(socket.getOutputStream(), request.toString());
                JSONObject reply = receive(socket, 5000);
                String reply_to = reply == null ? null : reply.optString("reply_to", null);
                String reply_peer = reply == null ? null : reply.optString("peer_id", null);
                String reply_session = reply == null ? null : reply.optString("session_id", null);
                if (reply != null && "ACK".equals(reply.getString("type"))
                        && ChatRules.matchesAck(request.getString("message_id"), reply_to,
                            reply_peer, reply_session, peer.peer_id, peer.session_id)) {
                    entry.state = "accepted";
                } else {
                    entry.state = "uncertain";
                    report(session, getString(R.string.chat_unaccepted, peer.name));
                }
            } finally {
                session.sockets.remove(socket);
            }
        } catch (Exception error) {
            entry.state = "failed";
            report(session, getString(R.string.chat_failed, error));
        }
        update_chat_ui(session);
    }

    private void choose_chat_scope(boolean dm) {
        chat_dm = dm;
        chat_scope_room.setSelected(!dm);
        chat_scope_dm.setSelected(dm);
        update_chat_ui(current);
    }

    private void send_chat_from_composer() {
        Session session = current;
        PeerSnapshot peer = selected_peer;
        if (session == null || !session.running || peer == null
                || !peer.has_capability("chat_v1")) {
            report(session, getString(R.string.chat_no_peer));
            return;
        }
        String text = chat_input.getText().toString();
        if (!ChatRules.validText(text)) {
            chat_input.setError(getString(R.string.chat_invalid_text));
            return;
        }
        chat_input.setError(null);
        chat_input.setText("");
        send_chat(peer, chat_dm ? "dm" : "room", text);
    }

    private void update_chat_ui(Session session) {
        runOnUiThread(() -> {
            if (session != null && current != session) return;
            if (session == null && current != null) return;
            Session active = current;
            PeerSnapshot peer = selected_peer;
            boolean live = active != null && active.running && peer != null
                && peer.has_capability("chat_v1");
            if (peer == null) {
                chat_peer_label.setText(R.string.no_selected_device);
            } else {
                chat_peer_label.setText(getString(R.string.selected_target_format,
                    peer.name, peer.ip, peer.tcp_port));
            }
            chat_send.setEnabled(live);
            StringBuilder history = new StringBuilder();
            if (active != null) {
                synchronized (active.chat_history) {
                    for (ChatEntry entry : active.chat_history) {
                        history.append(entry.sender).append(" [")
                            .append(entry.scope).append(", ")
                            .append(entry.state).append("] ");
                        history.append(entry.text).append('\n');
                    }
                }
            }
            chat_history.setText(history.length() == 0
                ? getString(R.string.chat_empty) : history.toString());
        });
    }

    private void choose_file_to_send() {
        Session session = current;
        PeerSnapshot peer = selected_peer;
        if (session == null || peer == null || !peer.has_capability("file_v1")) {
            update_transfer_ui(null, getString(R.string.select_file_peer), 0, false);
            return;
        }
        synchronized (session) {
            if (session.transfer != null) {
                update_transfer_ui(session.transfer, getString(R.string.transfer_busy), 0, false);
                return;
            }
        }
        pending_send_peer = peer;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
        launch_picker(intent, REQUEST_OPEN_FILE);
    }

    private void accept_incoming_file() {
        Session session = current;
        TransferTask task = session == null ? null : session.transfer;
        if (task == null || !task.incoming) return;
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream")
            .putExtra(Intent.EXTRA_TITLE, task.name);
        launch_picker(intent, REQUEST_CREATE_FILE);
    }

    private void decline_incoming_file() {
        Session session = current;
        TransferTask task = session == null ? null : session.transfer;
        if (task == null || !task.incoming) return;
        task.declined = true;
        task.decision.countDown();
        update_transfer_ui(task, getString(R.string.transfer_declining), 0, false);
    }

    private void cancel_transfer() {
        Session session = current;
        TransferTask task = session == null ? null : session.transfer;
        if (task == null) return;
        task.cancelled = true;
        task.provider_signal.cancel();
        close_provider_io(task);
        task.decision.countDown();
        if (task.socket != null) {
            try {
                task.socket.close();
            } catch (IOException error) {
                Log.d(TAG, "Transfer cancel close", error);
            }
        }
        update_transfer_ui(task, getString(R.string.transfer_cancelling), 0, false);
    }

    private void launch_picker(Intent intent, int request_code) {
        picker_active = true;
        int generation = ++picker_generation;
        if (picker_timeout != null) main_handler.removeCallbacks(picker_timeout);
        picker_timeout = () -> {
            if (picker_active && picker_generation == generation) {
                picker_active = false;
                Session session = current;
                if (session != null && session.transfer != null) {
                    session.transfer.cancelled = true;
                    session.transfer.provider_signal.cancel();
                    close_provider_io(session.transfer);
                    session.transfer.decision.countDown();
                }
                stop_session();
            }
        };
        main_handler.postDelayed(picker_timeout, 65000);
        try {
            startActivityForResult(intent, request_code);
        } catch (RuntimeException error) {
            picker_active = false;
            main_handler.removeCallbacks(picker_timeout);
            picker_timeout = null;
            pending_send_peer = null;
            report(current, getString(R.string.picker_failed, error));
        }
    }

    @Override protected void onActivityResult(int request_code, int result_code, Intent data) {
        super.onActivityResult(request_code, result_code, data);
        picker_active = false;
        if (picker_timeout != null) main_handler.removeCallbacks(picker_timeout);
        picker_timeout = null;
        Uri uri = result_code == RESULT_OK && data != null ? data.getData() : null;
        if (request_code == REQUEST_OPEN_FILE) {
            PeerSnapshot peer = pending_send_peer;
            pending_send_peer = null;
            PeerSnapshot refreshed = selected_peer;
            if (uri != null && peer != null && refreshed != null
                    && peer.session_id.equals(refreshed.session_id)) {
                begin_send_file(uri, refreshed);
            } else if (uri != null && peer != null) {
                update_transfer_ui(null, getString(R.string.transfer_peer_unavailable), 0, false);
            }
            return;
        }
        if (request_code == REQUEST_CREATE_FILE) {
            Session session = current;
            TransferTask task = session == null ? null : session.transfer;
            if (task == null || !task.incoming) return;
            if (uri == null) {
                task.declined = true;
            } else {
                task.destination = uri;
            }
            task.decision.countDown();
        }
    }

    private void begin_send_file(Uri uri, PeerSnapshot peer) {
        Session session = current;
        if (session == null || !session.running) return;
        TransferTask task = new TransferTask(UUID.randomUUID().toString(), false);
        synchronized (session) {
            if (!session.running || session.transfer != null) {
                update_transfer_ui(null, getString(R.string.transfer_busy), 0, false);
                return;
            }
            session.transfer = task;
        }
        update_transfer_ui(task, getString(R.string.transfer_hashing), 0, false);
        try {
            session.workers.execute(() -> send_file(session, task, uri, peer));
        } catch (RejectedExecutionException error) {
            clear_transfer(session, task, getString(R.string.transfer_queue_full));
        }
    }

    private void send_file(Session session, TransferTask task, Uri uri, PeerSnapshot peer) {
        try {
            task.name = TransferRules.safe_file_name(display_name(task, uri));
            HashResult source = hash_uri(task, uri);
            task.size = source.size;
            task.digest = source.digest;
            check_transfer(session, task);
            try (Socket socket = new Socket()) {
                task.socket = socket;
                session.sockets.add(socket);
                socket.connect(new InetSocketAddress(peer.ip, peer.tcp_port), 3000);
                JSONObject body = new JSONObject()
                    .put("transfer_id", task.id).put("name", task.name)
                    .put("size", task.size).put("sha256", task.digest)
                    .put("to_session", peer.session_id);
                Frames.send(socket.getOutputStream(), message(session, "FILE_OFFER", body).toString());
                update_transfer_ui(task, getString(R.string.transfer_waiting_accept), 0, false);
                JSONObject reply = receive(socket, 65000);
                validate_transfer_reply(reply, task, peer);
                if ("FILE_DECLINE".equals(reply.getString("type"))) {
                    clear_transfer(session, task, getString(R.string.transfer_declined));
                    return;
                }
                if (!"FILE_ACCEPT".equals(reply.getString("type"))) {
                    throw new IOException("Expected FILE_ACCEPT");
                }
                MessageDigest sent_digest = sha256();
                long offset = 0;
                try (InputStream stream = require_stream(task, uri)) {
                    task.provider_io = stream;
                    byte[] buffer = new byte[TransferRules.CHUNK_SIZE];
                    int count;
                    long last_update = 0;
                    while ((count = stream.read(buffer)) >= 0) {
                        if (count == 0) continue;
                        check_transfer(session, task);
                        if (offset + count > task.size) {
                            throw new IOException("Source file grew after hashing");
                        }
                        byte[] chunk = java.util.Arrays.copyOf(buffer, count);
                        JSONObject chunk_body = new JSONObject()
                            .put("transfer_id", task.id).put("offset", offset)
                            .put("data", Base64.getEncoder().encodeToString(chunk));
                        Frames.send(socket.getOutputStream(),
                            message(session, "FILE_CHUNK", chunk_body).toString());
                        offset += count;
                        sent_digest.update(chunk);
                        long now = SystemClock.elapsedRealtime();
                        if (now - last_update >= 100 || offset == task.size) {
                            last_update = now;
                            update_transfer_progress(task, offset, task.size,
                                getString(R.string.transfer_sending));
                        }
                    }
                } finally {
                    task.provider_io = null;
                }
                if (offset != task.size
                        || !TransferRules.hex(sent_digest.digest()).equals(task.digest)) {
                    throw new IOException("Source file changed after hashing");
                }
                Frames.send(socket.getOutputStream(), message(session, "FILE_DONE",
                    new JSONObject().put("transfer_id", task.id)).toString());
                update_transfer_ui(task, getString(R.string.transfer_verifying), 100, false);
                reply = receive(socket, VERIFY_TIMEOUT_MS);
                validate_transfer_reply(reply, task, peer);
                JSONObject result = reply.getJSONObject("body");
                if (!"FILE_RESULT".equals(reply.getString("type"))
                        || !"verified".equals(result.optString("status"))
                        || require_integer(result, "size", 0,
                            TransferRules.MAX_FILE_SIZE) != task.size
                        || !task.digest.equals(result.optString("sha256"))) {
                    throw new IOException("Receiver did not verify the file");
                }
                clear_transfer(session, task, getString(R.string.transfer_sent, task.name));
            } finally {
                session.sockets.remove(task.socket);
                task.socket = null;
            }
        } catch (Exception error) {
            clear_transfer(session, task, task.cancelled
                ? getString(R.string.transfer_cancelled)
                : getString(R.string.transfer_failed, error));
        }
    }

    private void receive_file(Session session, Socket socket, JSONObject offer) throws Exception {
        JSONObject body = offer.getJSONObject("body");
        String identifier = DiscoveryRules.canonical_uuid(body.getString("transfer_id"));
        if (!session.id.equals(body.getString("to_session"))) {
            throw new IOException("Offer addressed to another session");
        }
        String name = body.getString("name");
        if (!TransferRules.valid_file_name(name)) {
            throw new IOException("Unsafe offered file name");
        }
        long size = require_integer(body, "size", 0, TransferRules.MAX_FILE_SIZE);
        String digest = body.getString("sha256");
        if (!TransferRules.valid_digest(digest)) throw new IOException("Invalid offered digest");
        TransferTask task = new TransferTask(identifier, true);
        task.socket = socket;
        task.name = name;
        task.size = size;
        task.digest = digest;
        task.remote_peer_id = offer.getString("peer_id");
        task.remote_session_id = offer.getString("session_id");
        synchronized (session) {
            if (session.transfer != null) {
                send_transfer_message(session, socket, task, "FILE_DECLINE", new JSONObject());
                return;
            }
            session.transfer = task;
        }
        update_transfer_ui(task, getString(R.string.incoming_file, name, size), 0, true);
        report(session, getString(R.string.incoming_file, name, size));
        File temporary = null;
        boolean accepted = false;
        boolean saved = false;
        try {
            await_transfer_decision(task, socket);
            check_transfer(session, task);
            if (task.declined || task.destination == null) {
                send_transfer_message(session, socket, task, "FILE_DECLINE", new JSONObject());
                clear_transfer(session, task, getString(R.string.transfer_declined));
                return;
            }
            temporary = File.createTempFile("lman-", ".part", getCacheDir());
            send_transfer_message(session, socket, task, "FILE_ACCEPT", new JSONObject());
            accepted = true;
            MessageDigest received_digest = sha256();
            long count = 0;
            try (FileOutputStream output = new FileOutputStream(temporary)) {
                while (true) {
                    check_transfer(session, task);
                    JSONObject message = receive(socket);
                    validate_transfer_sender(message, task);
                    if ("FILE_DONE".equals(message.getString("type"))) {
                        if (count != task.size) throw new IOException("File ended early");
                        break;
                    }
                    if (!"FILE_CHUNK".equals(message.getString("type"))) {
                        throw new IOException("Expected FILE_CHUNK or FILE_DONE");
                    }
                    JSONObject chunk_body = message.getJSONObject("body");
                    if (require_integer(chunk_body, "offset", 0,
                            TransferRules.MAX_FILE_SIZE) != count) {
                        throw new IOException("Unexpected file chunk offset");
                    }
                    byte[] chunk = TransferRules.decode_chunk(chunk_body.getString("data"));
                    if (count + chunk.length > task.size) {
                        throw new IOException("Chunk exceeds offered file size");
                    }
                    output.write(chunk);
                    received_digest.update(chunk);
                    count += chunk.length;
                    update_transfer_progress(task, count, task.size,
                        getString(R.string.transfer_receiving));
                }
                output.flush();
                output.getFD().sync();
            }
            String actual_digest = TransferRules.hex(received_digest.digest());
            if (!actual_digest.equals(task.digest)) {
                throw new IOException("Received file failed SHA-256 verification");
            }
            copy_to_destination(task, temporary);
            HashResult destination = hash_uri(task, task.destination);
            if (destination.size != task.size || !destination.digest.equals(task.digest)) {
                throw new IOException("Saved file failed SHA-256 verification");
            }
            saved = true;
            JSONObject result = new JSONObject().put("status", "verified")
                .put("size", task.size).put("sha256", task.digest);
            send_transfer_message(session, socket, task, "FILE_RESULT", result);
            clear_transfer(session, task, getString(R.string.transfer_received, task.name));
        } catch (Exception error) {
            if (!accepted) {
                try {
                    send_transfer_message(session, socket, task, "FILE_DECLINE", new JSONObject());
                } catch (Exception ignored) {
                    Log.d(TAG, "Could not decline failed offer", ignored);
                }
            }
            clear_transfer(session, task, task.cancelled
                ? getString(R.string.transfer_cancelled)
                : getString(R.string.transfer_failed, error));
            throw error;
        } finally {
            if (temporary != null && !temporary.delete()) {
                Log.w(TAG, "Could not delete transfer temporary file");
            }
            if (!saved && task.destination != null) {
                try {
                    getContentResolver().delete(task.destination, null, null);
                } catch (RuntimeException error) {
                    Log.w(TAG, "Could not delete failed destination", error);
                }
            }
        }
    }

    private String display_name(TransferTask task, Uri uri) {
        try (Cursor cursor = getContentResolver().query(
                uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null,
                task.provider_signal)) {
            if (cursor != null && cursor.moveToFirst()) {
                int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (column >= 0 && !cursor.isNull(column)) return cursor.getString(column);
            }
        } catch (RuntimeException error) {
            Log.w(TAG, "Could not read document display name", error);
        }
        return "shared-file";
    }

    private InputStream require_stream(TransferTask task, Uri uri) throws IOException {
        ParcelFileDescriptor descriptor = getContentResolver().openFileDescriptor(
            uri, "r", task.provider_signal);
        if (descriptor == null) throw new IOException("Document provider returned no input stream");
        return new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
    }

    private HashResult hash_uri(TransferTask task, Uri uri) throws IOException {
        MessageDigest digest = sha256();
        long size = 0;
        try (InputStream stream = require_stream(task, uri)) {
            task.provider_io = stream;
            byte[] buffer = new byte[TransferRules.CHUNK_SIZE];
            int count;
            while ((count = stream.read(buffer)) >= 0) {
                if (count == 0) continue;
                if (task.cancelled) throw new IOException("Transfer cancelled");
                size += count;
                if (size > TransferRules.MAX_FILE_SIZE) {
                    throw new IOException("File exceeds the 1 GiB limit");
                }
                digest.update(buffer, 0, count);
            }
        } finally {
            task.provider_io = null;
        }
        return new HashResult(size, TransferRules.hex(digest.digest()));
    }

    private void await_transfer_decision(TransferTask task, Socket socket) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 60000;
        InputStream stream = socket.getInputStream();
        while (task.decision.getCount() > 0) {
            if (task.cancelled) throw new IOException("Transfer cancelled");
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                task.declined = true;
                return;
            }
            socket.setSoTimeout((int) Math.min(250, remaining));
            try {
                int value = stream.read();
                if (value < 0) throw new IOException("Sender disconnected before acceptance");
                throw new IOException("Sender transmitted data before acceptance");
            } catch (SocketTimeoutException ignored) {
                // Polling detects disconnects without consuming a valid post-accept frame.
            }
        }
    }

    private static long require_integer(JSONObject value, String key, long minimum, long maximum)
            throws IOException, JSONException {
        Object raw = value.get(key);
        if (!(raw instanceof Integer)) throw new IOException(key + " must be an integer");
        long number = ((Integer) raw).longValue();
        if (number < minimum || number > maximum) {
            throw new IOException(key + " is outside the allowed range");
        }
        return number;
    }

    private static MessageDigest sha256() throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException error) {
            throw new IOException("SHA-256 unavailable", error);
        }
    }

    private static void close_provider_io(TransferTask task) {
        Closeable stream = task.provider_io;
        if (stream == null) return;
        Thread closer = new Thread(() -> {
            try {
                stream.close();
            } catch (IOException error) {
                Log.d(TAG, "Provider stream close", error);
            }
        }, "lman-provider-close");
        closer.setDaemon(true);
        closer.start();
    }

    private void check_transfer(Session session, TransferTask task) throws IOException {
        if (!session.running || task.cancelled || session.transfer != task) {
            throw new IOException("Transfer cancelled");
        }
    }

    private void validate_transfer_reply(JSONObject reply, TransferTask task,
                                         PeerSnapshot peer) throws Exception {
        if (reply == null
                || !peer.peer_id.equals(reply.getString("peer_id"))
                || !peer.session_id.equals(reply.getString("session_id"))
                || !task.id.equals(reply.getJSONObject("body").getString("transfer_id"))) {
            throw new IOException("Transfer reply identity mismatch");
        }
    }

    private void validate_transfer_sender(JSONObject value, TransferTask task) throws Exception {
        if (value == null
                || !task.remote_peer_id.equals(value.getString("peer_id"))
                || !task.remote_session_id.equals(value.getString("session_id"))
                || !task.id.equals(value.getJSONObject("body").getString("transfer_id"))) {
            throw new IOException("Transfer sender identity mismatch");
        }
    }

    private void send_transfer_message(Session session, Socket socket, TransferTask task,
                                       String type, JSONObject values) throws Exception {
        JSONObject body = new JSONObject().put("transfer_id", task.id);
        java.util.Iterator<String> keys = values.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            body.put(key, values.get(key));
        }
        Frames.send(socket.getOutputStream(), message(session, type, body).toString());
    }

    private void copy_to_destination(TransferTask task, File source) throws IOException {
        ParcelFileDescriptor descriptor = getContentResolver().openFileDescriptor(
            task.destination, "rwt", task.provider_signal);
        if (descriptor == null) throw new IOException("Document provider returned no output stream");
        OutputStream raw = new ParcelFileDescriptor.AutoCloseOutputStream(descriptor);
        try (InputStream input = new FileInputStream(source); OutputStream output = raw) {
            task.provider_io = output;
            byte[] buffer = new byte[TransferRules.CHUNK_SIZE];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count == 0) continue;
                if (task.cancelled) throw new IOException("Transfer cancelled");
                output.write(buffer, 0, count);
            }
            output.flush();
        } finally {
            task.provider_io = null;
        }
    }

    private void update_transfer_progress(TransferTask task, long count, long total,
                                          String state) {
        int progress = total == 0 ? 100 : (int) Math.min(100, count * 100 / total);
        update_transfer_ui(task,
            getString(R.string.transfer_progress, state, count, total), progress, false);
    }

    private void clear_transfer(Session session, TransferTask task, String state) {
        synchronized (session) {
            if (session.transfer == task) session.transfer = null;
        }
        report(session, state);
        update_transfer_ui(task, state, 100, false);
    }

    private void update_transfer_ui(TransferTask task, String state, int progress,
                                    boolean incoming_offer) {
        runOnUiThread(() -> {
            Session session = current;
            if (task != null && session == null) return;
            if (task != null && session.transfer != null && session.transfer != task) return;
            boolean active = task != null && session != null && session.transfer == task;
            transfer_status.setText(state);
            transfer_progress.setProgress(Math.max(0, Math.min(100, progress)));
            accept_file_button.setEnabled(active && incoming_offer);
            decline_file_button.setEnabled(active && incoming_offer);
            cancel_transfer_button.setEnabled(active);
            send_file_button.setEnabled(session != null && !active && selected_peer != null
                && selected_peer.has_capability("file_v1"));
            if (incoming_offer) {
                Toast.makeText(this, state, Toast.LENGTH_LONG).show();
            }
        });
    }

    private void probe() {
        Session session = current;
        String host = host_input.getText().toString().trim();
        if (session == null || host.isEmpty()) {
            host_input.setError(getString(R.string.probe_input_error));
            report(null, getString(R.string.probe_input_error));
            return;
        }
        host_input.setError(null);
        int port = host.equals(selected_host) ? selected_port : 50002;
        probe_status.setText(R.string.probe_running);
        try {
            session.workers.execute(() -> {
                try (Socket socket = new Socket()) {
                    session.sockets.add(socket);
                    try {
                        socket.connect(new InetSocketAddress(host, port), 3000);
                        if (!session.running) return;
                        for (String text : new String[]{"hello", "नमस्ते", repeated_x(100000), "end"}) {
                            JSONObject request = message(
                                session, "ECHO", new JSONObject().put("text", text));
                            Frames.send(socket.getOutputStream(), request.toString());
                            JSONObject reply = receive(socket);
                            if (reply == null || !"ECHO_REPLY".equals(reply.getString("type"))
                                    || !request.getString("message_id").equals(reply.getString("reply_to"))
                                    || !text.equals(reply.getJSONObject("body").getString("text"))) {
                                throw new IOException("Echo mismatch");
                            }
                            int length = text.codePointCount(0, text.length());
                            report(session, getResources().getQuantityString(
                                R.plurals.verified_vector, length, length));
                        }
                        runOnUiThread(() -> {
                            if (current == session) probe_status.setText(R.string.probe_success);
                        });
                    } finally {
                        session.sockets.remove(socket);
                    }
                } catch (Exception error) {
                    report(session, getString(R.string.probe_failed, error));
                    runOnUiThread(() -> {
                        if (current == session) {
                            probe_status.setText(getString(R.string.probe_failed, error));
                        }
                    });
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException error) {
            report(session, getString(R.string.probe_queue_full));
            probe_status.setText(R.string.probe_queue_full);
        }
    }

    private static String short_id(String value) {
        return value.length() <= 8 ? value : value.substring(0, 8) + "…";
    }

    private static String repeated_x(int count) {
        char[] value = new char[count];
        java.util.Arrays.fill(value, 'x');
        return new String(value);
    }

    private static String decode_utf8(byte[] data, int offset, int length) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data, offset, length)).toString();
        } catch (java.nio.charset.CharacterCodingException error) {
            throw new IOException("Invalid UTF-8", error);
        }
    }

    private JSONObject parse(String json) throws IOException, JSONException {
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            Object value = read_json(reader, 0);
            if (!(value instanceof JSONObject) || reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IOException("Expected one JSON object");
            }
            return (JSONObject) value;
        }
    }

    private Object read_json(JsonReader reader, int depth) throws IOException, JSONException {
        if (depth > 64) throw new IOException("JSON nesting limit");
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                JSONObject object = new JSONObject();
                Set<String> keys = new HashSet<>();
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (!keys.add(key)) throw new IOException("Duplicate JSON key");
                    object.put(key, read_json(reader, depth + 1));
                }
                reader.endObject();
                return object;
            case BEGIN_ARRAY:
                JSONArray array = new JSONArray();
                reader.beginArray();
                while (reader.hasNext()) array.put(read_json(reader, depth + 1));
                reader.endArray();
                return array;
            case STRING:
                return reader.nextString();
            case BOOLEAN:
                return reader.nextBoolean();
            case NULL:
                reader.nextNull();
                return JSONObject.NULL;
            case NUMBER:
                String number = reader.nextString();
                try {
                    return Integer.valueOf(number);
                } catch (NumberFormatException not_integer) {
                    double value = Double.parseDouble(number);
                    if (!Double.isFinite(value)) throw new IOException("Invalid JSON number");
                    return value;
                }
            default:
                throw new IOException("Invalid JSON token");
        }
    }
}
