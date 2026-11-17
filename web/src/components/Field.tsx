import { forwardRef, useId } from 'react'
import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'

interface BaseProps {
  label?: string
  hint?: ReactNode
  error?: string | null
  required?: boolean
  /** Show the "optional" suffix after the label. Off for fields where it is noise. */
  markOptional?: boolean
  className?: string
}

/** Shared shell: label + control + hint/error, with the aria wiring done once. */
function Shell({
  id,
  label,
  hint,
  error,
  required,
  markOptional = true,
  className,
  children,
}: BaseProps & { id: string; children: ReactNode }) {
  return (
    <div className={className}>
      {label ? (
        <label htmlFor={id} className="tg-label">
          {label}
          {required ? (
            <span className="ml-0.5 text-danger" aria-hidden="true">
              *
            </span>
          ) : null}
          {!required && markOptional ? (
            <span className="ml-1.5 normal-case text-faint">optional</span>
          ) : null}
        </label>
      ) : null}
      {children}
      {error ? (
        <p id={`${id}-error`} className="mt-1.5 flex items-start gap-1.5 text-xs text-danger">
          <Icon name="alert" size={13} className="mt-px shrink-0" />
          <span>{error}</span>
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="tg-hint">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'>, BaseProps {
  /** Rendered inside the control on the left. */
  icon?: 'search' | 'link' | 'key'
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { label, hint, error, required, markOptional, className, icon, ...rest },
  ref,
) {
  const autoId = useId()
  const id = rest.name ? `f-${rest.name}` : autoId
  return (
    <Shell
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      markOptional={markOptional}
      className={className}
    >
      <div className="relative">
        {icon ? (
          <Icon
            name={icon}
            size={14}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
          />
        ) : null}
        <input
          ref={ref}
          id={id}
          className={cn('tg-input', icon && 'pl-8', error && 'border-danger focus:border-danger')}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
          aria-required={required || undefined}
          {...rest}
        />
      </div>
    </Shell>
  )
})

export interface TextAreaFieldProps
  extends Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'id'>,
    BaseProps {}

export function TextAreaField({
  label,
  hint,
  error,
  required,
  markOptional,
  className,
  ...rest
}: TextAreaFieldProps) {
  const autoId = useId()
  const id = rest.name ? `f-${rest.name}` : autoId
  return (
    <Shell
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      markOptional={markOptional}
      className={className}
    >
      <textarea
        id={id}
        rows={rest.rows ?? 3}
        className={cn('tg-input h-auto py-2 leading-relaxed', error && 'border-danger')}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        {...rest}
      />
    </Shell>
  )
}

export interface SelectFieldProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id'>, BaseProps {
  options: Array<{ value: string; label: string }>
}

export function SelectField({
  label,
  hint,
  error,
  required,
  markOptional,
  className,
  options,
  ...rest
}: SelectFieldProps) {
  const autoId = useId()
  const id = rest.name ? `f-${rest.name}` : autoId
  return (
    <Shell
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      markOptional={markOptional}
      className={className}
    >
      <div className="relative">
        <select
          id={id}
          className={cn('tg-input appearance-none pr-8', error && 'border-danger')}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
          {...rest}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <Icon
          name="chevron-down"
          size={14}
          className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-muted"
        />
      </div>
    </Shell>
  )
}

/** Toggle switch with a real checkbox underneath so it is keyboard + SR friendly. */
export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
  disabled?: boolean
}) {
  const id = useId()
  return (
    <div className="flex items-start gap-2.5">
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors',
          checked ? 'border-accent bg-accent' : 'border-border-strong bg-surface-3',
          disabled && 'cursor-not-allowed opacity-50',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 h-3.5 w-3.5 rounded-full bg-white transition-transform',
            checked ? 'translate-x-[18px]' : 'translate-x-0.5',
          )}
        />
      </button>
      <div className="min-w-0">
        <div className="text-xs font-medium text-text">{label}</div>
        {description ? <div className="text-2xs text-muted">{description}</div> : null}
      </div>
    </div>
  )
}