/**
 * A Button inside a form does not submit it unless asked.
 *
 * The component rendered a bare <button>, which HTML defaults to type=submit.
 * All 91 buttons then sitting in a form passed a type explicitly; the first
 * omission would have submitted the form instead of opening a modal, with
 * nothing to show for it.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

import { Button } from '../Button'

describe('Button type', () => {
  it('does not submit the form it sits in', () => {
    const onSubmit = vi.fn(e => e.preventDefault())
    render(<form onSubmit={onSubmit}><Button>Open</Button></form>)
    fireEvent.click(screen.getByText('Open'))
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('still submits when asked to', () => {
    const onSubmit = vi.fn(e => e.preventDefault())
    render(<form onSubmit={onSubmit}><Button type="submit">Save</Button></form>)
    fireEvent.click(screen.getByText('Save'))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('keeps the caller onClick either way', () => {
    const onClick = vi.fn()
    render(<Button onClick={onClick}>Act</Button>)
    fireEvent.click(screen.getByText('Act'))
    expect(onClick).toHaveBeenCalledTimes(1)
  })
})
