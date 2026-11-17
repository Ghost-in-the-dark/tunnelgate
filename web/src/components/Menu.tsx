import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'
import type { IconName } from './Icon'

export interface MenuItem {
  label: string
  icon?: IconName
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
  /** Shown as a tooltip and aria-describedby when disabled. */
  disabledReason?: string
  separatorBefore?: boolean
}

/**
 * Row action menu. Small hand-rolled popover rather than a library:
 * keyboard support is the part that matters - ArrowUp/Down, Home/End, Enter,
 * Escape, and click-outside-to-close are all implemented below.
 */
export function ActionMenu({
  items,
  label,
  align = 'right',
  trigger,
}: {
  items: MenuItem[]
  label: string
  align?: 'left' | 'right'
  trigger?: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(-1)
  const rootRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  const menuId = useId()

  useEffect(() => {
    if (!open) return
    const onDocDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocDown)
    return () => document.removeEventListener('mousedown', onDocDown)
  }, [open])

  // Flip the popover up when it would overflow the viewport.
  const [flipUp, setFlipUp] = useState(false)
  useLayoutEffect(() => {
    if (!open || !listRef.current) return
    const rect = listRef.current.getBoundingClientRect()
    setFlipUp(rect.bottom > window.innerHeight - 8)
  }, [open])

  const enabledIndexes = items.map((it, i) => (it.disabled ? -1 : i)).filter((i) => i >= 0)

  const focusItem = (index: number) => {
    setActive(index)
    const nodes = listRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]')
    nodes?.[index]?.focus()
  }

  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      setOpen(false)
      btnRef.current?.focus()
      return
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const dir = e.key === 'ArrowDown' ? 1 : -1
      const pos = enabledIndexes.indexOf(active)
      const next = enabledIndexes[(pos + dir + enabledIndexes.length) % enabledIndexes.length]
      if (next !== undefined) focusItem(next)
      return
    }
    if (e.key === 'Home') {
      e.preventDefault()
      const first = enabledIndexes[0]
      if (first !== undefined) focusItem(first)
      return
    }
    if (e.key === 'End') {
      e.preventDefault()
      const last = enabledIndexes[enabledIndexes.length - 1]
      if (last !== undefined) focusItem(last)
    }
  }

  const openMenu = () => {
    setOpen(true)
    // Focus the first enabled item on the next paint so screen readers land inside.
    window.requestAnimationFrame(() => {
      const first = enabledIndexes[0]
      if (first !== undefined) focusItem(first)
    })
  }

  return (
    <div ref={rootRef} className="relative inline-block">
      <button
        ref={btnRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={label}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            if (!open) openMenu()
          }
        }}
        className={cn(
          'inline-flex h-7 w-7 items-center justify-center rounded text-muted transition-colors',
          'hover:bg-surface-3 hover:text-text',
          open && 'bg-surface-3 text-text',
        )}
      >
        {trigger ?? <Icon name="more" size={15} />}
      </button>

      {open ? (
        <div
          ref={listRef}
          id={menuId}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKeyDown}
          className={cn(
            'absolute z-30 w-52 animate-pop-in overflow-hidden rounded border border-border bg-surface p-1 shadow-pop',
            align === 'right' ? 'right-0' : 'left-0',
            flipUp ? 'bottom-full mb-1' : 'top-full mt-1',
          )}
        >
          {items.map((item, i) => (
            <div key={item.label}>
              {item.separatorBefore ? <div className="my-1 h-px bg-border" role="separator" /> : null}
              <button
                type="button"
                role="menuitem"
                tabIndex={-1}
                disabled={item.disabled}
                title={item.disabled ? item.disabledReason : undefined}
                aria-describedby={item.disabled && item.disabledReason ? `${menuId}-r-${i}` : undefined}
                onClick={() => {
                  setOpen(false)
                  item.onSelect()
                }}
                className={cn(
                  'flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs transition-colors',
                  item.disabled
                    ? 'cursor-not-allowed text-faint'
                    : item.danger
                      ? 'text-danger hover:bg-danger/10'
                      : 'text-text hover:bg-surface-2',
                )}
              >
                {item.icon ? <Icon name={item.icon} size={13} className="shrink-0" /> : <span className="w-[13px]" />}
                <span className="truncate">{item.label}</span>
              </button>
              {item.disabled && item.disabledReason ? (
                <span id={`${menuId}-r-${i}`} className="sr-only">
                  {item.disabledReason}
                </span>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}
