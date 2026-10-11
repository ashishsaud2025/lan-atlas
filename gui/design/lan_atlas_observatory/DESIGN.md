---
name: LAN Atlas Observatory
colors:
  surface: '#060a10'
  surface-dim: '#060a10'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#131b28'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#cbdad4'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#85948f'
  outline-variant: '#3b4a45'
  surface-tint: '#2adec0'
  primary: '#46efcf'
  on-primary: '#00382e'
  primary-container: '#00d2b4'
  on-primary-container: '#005547'
  inverse-primary: '#006b5b'
  secondary: '#ddb7ff'
  on-secondary: '#490080'
  secondary-container: '#6f00be'
  on-secondary-container: '#d6a9ff'
  tertiary: '#ffce94'
  on-tertiary: '#472a00'
  tertiary-container: '#ffa824'
  on-tertiary-container: '#6a4200'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#57fbdb'
  primary-fixed-dim: '#2adec0'
  on-primary-fixed: '#00201a'
  on-primary-fixed-variant: '#005144'
  secondary-fixed: '#f0dbff'
  secondary-fixed-dim: '#ddb7ff'
  on-secondary-fixed: '#2c0051'
  on-secondary-fixed-variant: '#6900b3'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 30px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  title-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-code-lg:
    fontFamily: JetBrains Mono
    fontSize: 22px
    fontWeight: '700'
    lineHeight: 26px
    letterSpacing: -0.02em
  label-code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: -0.01em
  label-code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
    letterSpacing: 0.02em
  section-eyebrow:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.08em
rounded:
  sm: 0.25rem
  DEFAULT: 0.75rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  margin: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 1.75rem
---

## Brand & Style

This design system embodies the focused, quiet precision of a mission-control observatory engineered for local peer-to-peer telemetry and infrastructure discovery. Designed specifically for technical operators, systems engineers, and power users navigating zero-trust local fabrics, the interface communicates forensic reliability, calm spatial awareness, and crisp cryptographic clarity.

The visual style blends **Technical Minimalism** with **Subtle Cybernetic Instrumentation**:
- **Palette Discipline**: Graphite-black obsidian backdrops eliminate eye strain during prolonged analysis, punctuated strictly by semantic telemetry accents rather than decorative gradients.
- **Data-Dense Hierarchy**: Dense information architecture tempered by generous micro-padding, hairline structural grids, and razor-sharp typographic scale.
- **Honest Feedback**: Security states are explicit. Unverified or self-reported states glow with amber caution, verified cryptographic pairings present stable violet signals, and active network telemetry pulses with calibrated cyan.

## Colors

The color system operates on an absolute dark-mode paradigm tailored for hardware-accelerated desktop views. Surfaces are layered using deep obsidian and slate depths rather than arbitrary lighting models.

### Semantic Roles & Palette Application
- **Canvas & Backdrops**: Deep obsidian foundation (`#060a10`) anchoring the root application shell, with elevated structural panels, top bars, and cards resting on layered dark graphite tones (`#131b28` and `#141a24`).
- **Structural Lines & Outlines**: Hairline boundaries (`#1c2433` and `#222d3d`) delineate cards, split-panes, and headers without heavy physical drop shadows.
- **Precision Primary Accent (`#00d2b4`, `#26e6cb`)**: Reserved for active navigation selection, live probe indicators, current identity glyphs, and primary actionable triggers.
- **Cryptographic Secondary (`#a855f7`, `#c084fc`)**: Denotes authenticated trust rings, encrypted handshakes, pinned key signatures, and verified device certificates.
- **Telemetry Warning & Notice (`#f59e0b`, `#d97706`)**: Highlights unverified local domains, self-reported mDNS capabilities, and unauthenticated traffic banners with a deep amber container (`#1e160a`) framed by an amber perimeter (`#78350f`).
- **Neutrals & Labels (`#64748b`, `#94a3b8`, `#e2e8f0`)**: Micro-copy, category section headers, and unit denominators employ muted slate tones, guaranteeing maximum contrast for primary network values without visual clutter.

## Typography

The dual-typographic engine combines the legible, neutral ergonomics of **Inter** for human UI context and instructions with the technical rigor of **JetBrains Mono** for raw network metrics, cryptographic fingerprints, and status badges.

### Typographic Principles
- **Monospace Isolation**: Numeric metrics, session keys, MAC/IP addresses, latency readouts (`ms`), and port indicators must be rendered in `JetBrains Mono`. This preserves tabular vertical alignment across scanning tables and diagnostic logs.
- **Section Eyebrows**: Category markers (e.g., `CONTROL`, `SHARE`, `COMMUNITY`) use `section-eyebrow` in all caps with wide letter tracking (`0.08em`) to enforce structural orientation across narrow sidebars.
- **Stat Values**: Identity hashes and high-level card tallies leverage `label-code-lg` with tight letter spacing for high-density impact.

## Layout & Spacing

The workspace uses a dense, desktop-first split view composed of an invariant navigational rail (`220px`), an optional diagnostic sub-rail (`280px`), and a fluid central monitoring deck.

### Spatial Distribution & Metrics
- **Grid Structure**: The primary canvas features an 8px grid foundation. Stat blocks and hardware telemetry cards distribute dynamically across a multi-column fluid flex grid with `gutter: 1rem`.
- **Card Padding**: Interior panels, informational warning callouts, and metric blocks employ `space-lg` (`20px`) vertically and `space-xl` (`28px`) horizontally to balance high data density with rapid parsing.
- **Visual Separation**: Avoid heavy margin gutters between structural components. Instead, rely on unified 1px hairline borders (`#1c2433`) and cohesive column layouts to create an integrated workstation shell.

## Elevation & Depth

Elevation in this design system avoids simulated diffuse light sources and skeuomorphic drop shadows. Instead, visual hierarchy is achieved via **Tonal Planar Stacking** and **Subtle Edge Occlusion**.

### Planar Layers
- **Floor (Canvas)**: `#060a10` (Base application window).
- **Layer 1 (Side Navigation & Rail)**: `#0d1117` with a 1px border right `#1c2433`.
- **Layer 2 (Content Panels & Telemetry Cards)**: `#131b28` enclosed within hairline borders `#1c2433`.
- **Layer 3 (Modals, Overlays, Command Bar)**: `#141a24` resting on `#1f293d` perimeter strokes, supported by an ultra-subtle directional ambient shadow: `0 8px 32px rgba(0, 0, 0, 0.65)`.

### Focus and Active Boundaries
Interactive components (active navigation items, focused inputs) express proximity using calibrated luminance shifts and inner borders rather than outer glows. When an element is selected, its border shifts from `#1c2433` to precision teal (`#00d2b4` at 40% opacity) or fills cleanly with primary teal.

## Shapes

The shape system employs disciplined, precision-milled radiuses designed to mimic precision hardware consoles. 

- **Containers & Panels**: Standard telemetry cards, status banners, and system panels use a calibrated `12px` corner radius (`rounded` / `0.75rem`), ensuring crisp alignment against neighboring modules.
- **Controls & Buttons**: Action buttons, search bars, and dropdown triggers uniformly align to `6px - 8px` radii.
- **Security & Status Badges**: Indicator pills and warning capsules utilize a tighter `4px - 6px` geometry to keep badge corners tight and utilitarian rather than playful or bubbly.

## Components

### Buttons & Triggers
- **Primary Accent Action**: Solid `#00d2b4` fill with bold obsidian text (`#0a0d12`), `6px` radius, hover transition brightening to `#26e6cb`.
- **Secondary Ghost Action**: `#10151d` background, hairline border `#222d3d`, crisp slate text (`#94a3b8`), shifting on hover to border `#00d2b4` and text `#f8fafc`.
- **Global Command Search**: Monospace shortcut pills embedded directly inside the button (`Ctrl+K`), styled with `#1c2433` stroke and `#64748b` typography.

### Telemetry Cards
- Compact modules framing key metrics (`Nearby sessions`, `Advertised capabilities`, `Local identity`).
- Headings are styled in muted slate `body-sm` (`#94a3b8`). Values are emphasized with prominent `label-code-lg` typography in precision teal (`#00d2b4`) or crisp white.
- Thin `1px` border `#1c2433` on `#10151d` surfaces.

### Warning & Security Banners
- Dedicated notification containers for zero-trust security notifications (e.g., *Unverified local network*).
- Formed with a low-luminance amber-tinted background (`rgba(217, 119, 6, 0.08)`), framed by a precise border (`rgba(245, 158, 11, 0.25)`).
- Text rendered in warm amber (`#f59e0b`), avoiding high-stress alert reds for expected local peer disclosures.

### Status Pills & Cryptographic Badges
- **Unverified LAN**: Outlined pill, `#1e160a` fill, `#d97706` boundary, diamond vector glyph, uppercase monospace font (`label-code-sm`).
- **Verified LAN**: Outlined pill, `#1e122b` fill, `#a855f7` boundary, shield/lock glyph, bright violet text (`#c084fc`).

### Input Fields & Controls
- Low-profile inputs set within `#0c1017` with `#1c2433` borders.
- Focused state transitions smoothly to an interior hairline ring in `#00d2b4`. Text input uses `JetBrains Mono` for exact string inspection.