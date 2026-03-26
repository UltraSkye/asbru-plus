# Ásbrú Design Tokens

Single source of truth for spacing, sizing, radius, and typography. GTK3 CSS
does not support custom properties (`--var`), so these values must be applied
**by hand** when editing `_base.css`. Keep this file in sync.

## Spacing scale

| Token | Value | Use                                           |
|-------|-------|-----------------------------------------------|
| `xs`  | 4px   | Tight inner padding, icon gap                 |
| `sm`  | 8px   | Sibling gap, container padding                |
| `md`  | 12px  | Card / dialog inner padding                   |
| `lg`  | 16px  | Dialog gutter, frame inner padding            |
| `xl`  | 24px  | Section break, large dialog padding           |
| `xxl` | 32px  | Top-level page gutter                         |

## Radius scale

| Token  | Value | Use                                           |
|--------|-------|-----------------------------------------------|
| `sm`   | 4px   | Inline tags, treeview rows                    |
| `md`   | 8px   | Buttons, inputs, scrolled windows             |
| `lg`   | 12px  | Cards, frames, dialogs                        |
| `xl`   | 16px  | Large modal containers                        |
| `pill` | 999px | Switches, badges                              |

## Sizing

| Token         | Value | Use                                  |
|---------------|-------|--------------------------------------|
| `control-h`   | 32px  | Buttons, entries, spinbuttons        |
| `row-h`       | 36px  | Treeview row, list row               |
| `dialog-btn-h`| 36px  | Dialog action buttons                |
| `sidebar-h`   | 44px  | Sidebar tab item                     |
| `icon-sm`     | 16px  | Inline icons in rows / labels        |
| `icon-md`     | 20px  | Toolbar icons                        |
| `icon-lg`     | 24px  | Sidebar icons, large action buttons  |

## Typography

| Token     | Value  | Use                              |
|-----------|--------|----------------------------------|
| `text-xs` | 0.75em | Captions, hints                  |
| `text-sm` | 0.85em | Frame labels, secondary text     |
| `text-md` | 1em    | Body, default                    |
| `text-lg` | 1.15em | Section headers                  |
| `text-xl` | 1.5em  | Dialog titles                    |
| `text-xxl`| 2.5em  | Banner / hero text               |

## Color (refer per-theme files)

Per-theme CSS files (`asbru-dark/asbru.css`, `default/asbru.css`) own the
palette. Token names below are conventions, not CSS variables.

### Surfaces

| Token       | dark        | light     |
|-------------|-------------|-----------|
| `bg-window` | `#2d2d2d`   | `#fafafa` |
| `bg-elevated` | `#353535` | `#f6f5f4` |
| `bg-base`   | `#242424`   | `#ffffff` |
| `bg-button` | `#3a3a3a`   | `#e8e8e7` |
| `bg-hover`  | `#454545`   | `#f0f0ef` |

### Text

| Token        | dark      | light     |
|--------------|-----------|-----------|
| `text-primary`   | `#ffffff` | `#2e3436` |
| `text-secondary` | `#b6b6b6` | `#5e5c64` |

### Borders

| Token         | dark                            | light                       |
|---------------|---------------------------------|-----------------------------|
| `border-subtle` | `rgba(255,255,255,0.08)`      | `rgba(0,0,0,0.10)`          |
| `border-hover`  | `rgba(255,255,255,0.16)`      | `rgba(0,0,0,0.18)`          |

### Accent

| Token        | both themes |
|--------------|-------------|
| `accent`     | `#3584e4`   |
| `accent-hover` | `#4a90e8` |
| `destructive`  | `#e01b24` |
| `warning`      | `#ffd479` (dark) / `#b35900` (light) |
| `error`        | `#ff8a80` (dark) / `#c01c28` (light) |

## Animation / motion

| Token       | Value          | Use                              |
|-------------|----------------|----------------------------------|
| `t-fast`    | 100ms ease     | Color/border swaps               |
| `t-normal`  | 150ms ease     | Background/transform             |
| `t-slow`    | 250ms ease     | Layout shifts                    |
