# DevPulse Design System

> API Security Intelligence & LLM Cost Management Platform
> Inspired by Sentry, PostHog, Linear, and Vercel design systems.

---

## Brand Identity

### Name & Tagline
- **Name:** DevPulse
- **Tagline:** "API Security Intelligence. LLM Cost Control."
- **Personality:** Precise, trustworthy, vigilant, intelligent

### Logo
- Shield icon with a pulse/heartbeat line through it
- Represents continuous security monitoring
- Primary mark: Shield + Pulse
- Wordmark: "DevPulse" in Inter/Geist Semi-Bold

---

## Color System

### Primary Palette
```
--dp-brand:           #6366F1  /* Indigo-500 — primary actions, links */
--dp-brand-hover:     #4F46E5  /* Indigo-600 */
--dp-brand-subtle:    #EEF2FF  /* Indigo-50 — backgrounds */
```

### Semantic Colors
```
/* Severity indicators (critical for security dashboard) */
--dp-critical:        #DC2626  /* Red-600 */
--dp-critical-bg:     #FEF2F2  /* Red-50 */
--dp-high:            #EA580C  /* Orange-600 */
--dp-high-bg:         #FFF7ED  /* Orange-50 */
--dp-medium:          #CA8A04  /* Yellow-600 */
--dp-medium-bg:       #FEFCE8  /* Yellow-50 */
--dp-low:             #2563EB  /* Blue-600 */
--dp-low-bg:          #EFF6FF  /* Blue-50 */
--dp-info:            #6B7280  /* Gray-500 */
--dp-info-bg:         #F9FAFB  /* Gray-50 */

/* Status */
--dp-success:         #16A34A  /* Green-600 */
--dp-success-bg:      #F0FDF4  /* Green-50 */
--dp-warning:         #D97706  /* Amber-600 */
--dp-warning-bg:      #FFFBEB  /* Amber-50 */
--dp-error:           #DC2626  /* Red-600 */
--dp-error-bg:        #FEF2F2  /* Red-50 */
```

### Dark Theme (Primary)
```
--dp-bg-primary:      #0A0A0F  /* Near-black, inspired by Vercel */
--dp-bg-secondary:    #111118  /* Card backgrounds */
--dp-bg-tertiary:     #1A1A24  /* Elevated surfaces */
--dp-bg-hover:        #22222E  /* Hover states */
--dp-border:          #2A2A36  /* Borders */
--dp-border-subtle:   #1E1E28  /* Subtle borders */
--dp-text-primary:    #F4F4F5  /* Primary text */
--dp-text-secondary:  #A1A1AA  /* Secondary text */
--dp-text-tertiary:   #71717A  /* Muted text */
```

### Light Theme
```
--dp-bg-primary:      #FFFFFF
--dp-bg-secondary:    #FAFAFA
--dp-bg-tertiary:     #F4F4F5
--dp-bg-hover:        #F0F0F2
--dp-border:          #E4E4E7
--dp-border-subtle:   #F4F4F5
--dp-text-primary:    #18181B
--dp-text-secondary:  #52525B
--dp-text-tertiary:   #A1A1AA
```

---

## Typography

### Font Stack
```css
--dp-font-sans:   'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--dp-font-mono:   'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
```

### Scale
| Token          | Size   | Weight | Line Height | Use Case                    |
|----------------|--------|--------|-------------|-----------------------------|
| `display`      | 36px   | 700    | 1.1         | Page titles                 |
| `heading-1`    | 24px   | 600    | 1.2         | Section headers             |
| `heading-2`    | 20px   | 600    | 1.3         | Card titles                 |
| `heading-3`    | 16px   | 600    | 1.4         | Subsections                 |
| `body`         | 14px   | 400    | 1.5         | Default body text           |
| `body-small`   | 13px   | 400    | 1.5         | Secondary info              |
| `caption`      | 12px   | 500    | 1.4         | Labels, badges              |
| `code`         | 13px   | 400    | 1.6         | Code, endpoints, IDs        |

### Monospace Usage
- API endpoints: `GET /api/v1/scans`
- Risk scores: `87/100`
- Finding IDs: `API1:2023`
- Cost values: `$12.45`
- Token counts: `1,234,567`

---

## Layout

### Grid System
- **Max width:** 1440px (container), fluid below
- **Sidebar:** 240px collapsed to 52px (icon-only rail)
- **Content area:** Fluid with 24px padding
- **Gutter:** 16px between cards, 24px between sections

### Dashboard Layout (Inspired by Sentry + PostHog)
```
┌─────────────────────────────────────────────────┐
│  ┌──────┐  DevPulse          🔔  👤  ⚙️        │  ← Top bar (48px)
│  └──────┘                                       │
├────────┬────────────────────────────────────────┤
│        │  Dashboard                              │
│  📊    │  ┌──────────┬──────────┬──────────┐    │
│  Dash  │  │ Risk     │ Findings │ Cost     │    │  ← Metric cards
│        │  │ Score    │ Count    │ Today    │    │
│  🔍    │  │  87/100  │   24     │  $12.45  │    │
│  Scan  │  └──────────┴──────────┴──────────┘    │
│        │                                         │
│  📁    │  ┌─────────────────┬──────────────┐    │
│  Coll  │  │                 │              │    │  ← Charts row
│        │  │  Risk Trend     │  Findings    │    │
│  🛡️    │  │  (Line Chart)   │  (Donut)     │    │
│  Sec   │  │                 │              │    │
│        │  └─────────────────┴──────────────┘    │
│  📋    │                                         │
│  Comp  │  ┌─────────────────────────────────┐   │
│        │  │  Recent Scans / Activity Feed    │   │  ← Activity table
│  💰    │  │  ────────────────────────────    │   │
│  Cost  │  │  Collection A  |  87/100  |  3m  │   │
│        │  │  Collection B  |  45/100  |  1h  │   │
│  ⚙️    │  │  Collection C  |  92/100  |  2h  │   │
│  Set   │  └─────────────────────────────────┘   │
└────────┴────────────────────────────────────────┘
```

---

## Components

### Risk Score Badge
- Circular progress indicator with score in center
- Color-coded: Critical (red ≥80), High (orange ≥60), Medium (yellow ≥40), Low (blue <40)
- Subtle glow effect matching severity color
- Animated on value change

### Severity Pill
```
┌────────────┐
│ ● CRITICAL │  → Red background, white text
└────────────┘
┌────────────┐
│ ● HIGH     │  → Orange background, white text
└────────────┘
┌────────────┐
│ ● MEDIUM   │  → Yellow background, dark text
└────────────┘
┌────────────┐
│ ● LOW      │  → Blue background, white text
└────────────┘
```

### Metric Card
- Compact stat display (inspired by PostHog)
- Number prominently displayed in `heading-1`
- Label in `caption` above
- Trend arrow (↑↓→) with percentage change
- Subtle colored left border indicating trend

### Data Table (Inspired by Linear)
- Clean, borderless rows with hover highlight
- Sortable column headers with arrow indicators
- Inline severity pills and status badges
- Row actions on hover (view, rescan, export)
- Sticky header on scroll

### Finding Card
```
┌─────────────────────────────────────────────────┐
│  ● CRITICAL   API1:2023                         │
│                                                   │
│  Broken Object Level Authorization               │
│                                                   │
│  APIs expose endpoints that handle object         │
│  identifiers without proper authorization...      │
│                                                   │
│  Affected: GET /api/users/{id}, POST /api/orders │
│                                                   │
│  ┌──────────┐  ┌──────────┐                      │
│  │ Remediate│  │ Dismiss  │                      │
│  └──────────┘  └──────────┘                      │
└─────────────────────────────────────────────────┘
```

### Toast Notifications
- Slide in from top-right
- Auto-dismiss after 5s (configurable)
- Types: success (green), error (red), warning (amber), info (blue)
- Includes close button and optional action

---

## Charts & Data Visualization

### Risk Score Trend (Line Chart)
- Time series with gradient fill below line
- Color transitions based on score zones
- Tooltips showing exact value and date
- Comparison overlay for "before/after" scans

### Finding Distribution (Donut Chart)
- Severity breakdown with center total count
- Interactive segments with hover details
- Legend with counts below chart

### Cost Breakdown (Stacked Bar)
- Daily/weekly cost stacked by model
- Total cost line overlay
- Budget threshold line (dashed red)
- Hover shows per-model breakdown

### Activity Timeline
- Vertical timeline with event icons
- Color-coded by event type (scan, finding, alert)
- Expandable detail panels
- Relative timestamps ("3 min ago", "2 hours ago")

---

## Interaction Patterns

### Navigation
- Persistent left sidebar with icon + label
- Collapsible to icon-only on narrow viewports
- Active state: brand-colored left border + highlighted background
- Keyboard shortcuts: `G D` (dashboard), `G S` (scans), `G C` (collections)

### Loading States
- Skeleton screens for initial page load (not spinners)
- Inline loading indicators for data refresh
- Optimistic UI updates for mutations

### Empty States
- Friendly illustration + clear call-to-action
- "Import your first collection" / "Run your first scan"
- Link to documentation

### Error States
- Inline error messages with retry button
- Toast for non-critical errors
- Full-page error boundary for crashes
- Never show raw stack traces to users

---

## Responsive Breakpoints

| Breakpoint | Width    | Layout Changes                          |
|-----------|----------|------------------------------------------|
| `sm`      | 640px    | Sidebar hidden, hamburger menu           |
| `md`      | 768px    | Sidebar collapsed to icons               |
| `lg`      | 1024px   | Full sidebar, 2-column charts            |
| `xl`      | 1280px   | Full layout, 3-column metric cards       |
| `2xl`     | 1536px   | Max container width reached              |

---

## Accessibility

- WCAG 2.1 AA compliance target
- All interactive elements keyboard-accessible
- Focus rings visible (2px brand-colored outline)
- Color not sole indicator (icons/text supplement)
- Minimum contrast ratio: 4.5:1 for body text, 3:1 for large text
- Screen reader announcements for dynamic content updates
- Reduced motion support via `prefers-reduced-motion`

---

## Motion & Animation

### Principles
- Purposeful: animations convey meaning (loading, transitions, feedback)
- Quick: 150ms for micro-interactions, 300ms for transitions
- Eased: `cubic-bezier(0.4, 0, 0.2, 1)` for standard, `cubic-bezier(0, 0, 0.2, 1)` for enter

### Key Animations
- Risk score counter: Count-up animation on load
- Severity pills: Subtle pulse on critical/high findings
- Charts: Staggered reveal with fade-in
- Page transitions: Fade + slight upward slide (150ms)
- Sidebar collapse: Width transition (200ms)
