import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'
import type { IconName } from './Icon'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'subtle'
type Size = 'sm' | 'md' | 'lg' | 'icon'

const VARIANTS: Record<Variant, string> = {
  primary:
    'bg-accent text-white hover:bg-accent/90 active:bg-accent shadow-sm disabled:bg-accent/40 disabled:text-white/70',
  secondary:
    'border border-border bg-surface-2 text-text hover:bg-surface-3 hover:border-border-strong disabled:opacity-50',
  ghost: 'text-muted hover:bg-surface-2 hover:text-text disabled:opacity-40',
  danger: 'bg-danger text-white hover:bg-danger/90 disabled:bg-danger/40',
  subtle: 'bg-surface-3 text-text hover:bg-surface-3/70 disabled:opacity-50',
}

const SIZES: Record<Size, string> = {
  sm: 'h-7 gap-1.5 px-2.5 text-xs',
  md: 'h-9 gap-2 px-3.5 text-sm',
  lg: 'h-10 gap-2 px-4 text-sm',
  icon: 'h-8 w-8 justify-center',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  icon?: IconName
  iconRight?: IconName
  loading?: boolean
  children?: ReactNode
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, iconRight, loading, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={rest.type ?? 'button'}
      // A loading button must not be clickable twice, but it must stay focusable.
      aria-busy={loading || undefined}
      disabled={disabled || loading}
      className={cn(
        'relative inline-flex select-none items-center rounded font-medium transition-colors',
        'disabled:cursor-not-allowed',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...rest}
    >
      {loading ? (
        <Icon name="spinner" size={size === 'sm' ? 12 : 14} className="animate-spin" />
      ) : icon ? (
        <Icon name={icon} size={size === 'sm' ? 12 : 14} />
      ) : null}
      {children}
      {iconRight ? <Icon name={iconRight} size={size === 'sm' ? 12 : 14} /> : null}
    </button>
  )
})
