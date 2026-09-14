/**
 * Double-submit guards on the two shared submit surfaces (DUP-FE-015).
 *
 * `Button` spread `{...props}` AFTER computing `disabled={loading || props.disabled}`,
 * so any caller passing BOTH `loading` and an explicit `disabled` had the computed
 * value overwritten by its own prop. Five modals do exactly that
 * (UploadCACertModal, UploadCRLModal, RestoreModal, TakeOfflineModal,
 * CertDeploySection): while the request was in flight their submit button stayed
 * enabled, so Enter or a keyboard activation fired the action a second time.
 *
 * `FormModal` disables its submit only when the caller passes `loading`; four of
 * its six call sites do not, so it now also refuses re-entrant submits itself.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { Button } from '../Button'
import { FormModal } from '../FormModal'

describe('Button — loading is a real guard, not just a spinner', () => {
  it('stays disabled while loading even when the caller passes disabled={false}', () => {
    render(<Button loading disabled={false}>Save</Button>)
    expect(screen.getByRole('button')).toBeDisabled()
  })

  it('ignores a click while loading, with an explicit disabled={false}', () => {
    const onClick = vi.fn()
    render(<Button type="button" loading disabled={false} onClick={onClick}>Save</Button>)
    fireEvent.click(screen.getByRole('button'))
    expect(onClick).not.toHaveBeenCalled()
  })

  it('still honours an explicit disabled={true} when not loading', () => {
    render(<Button disabled>Save</Button>)
    expect(screen.getByRole('button')).toBeDisabled()
  })

  it('is enabled when neither loading nor disabled', () => {
    render(<Button>Save</Button>)
    expect(screen.getByRole('button')).not.toBeDisabled()
  })
})

describe('FormModal — refuses a re-entrant submit', () => {
  function renderWithSlowSubmit() {
    let release
    const gate = new Promise((resolve) => { release = resolve })
    const onSubmit = vi.fn(() => gate)
    const utils = render(
      <FormModal open onClose={() => {}} title="Create" onSubmit={onSubmit}>
        <input name="label" defaultValue="x" />
      </FormModal>
    )
    return { ...utils, onSubmit, release }
  }

  it('runs the handler once for three submits in flight', async () => {
    const { onSubmit, release } = renderWithSlowSubmit()
    const form = document.querySelector('form')

    fireEvent.submit(form)
    fireEvent.submit(form)
    fireEvent.submit(form)

    expect(onSubmit).toHaveBeenCalledTimes(1)

    release()
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
  })

  it('accepts a new submit once the first one has settled', async () => {
    const { onSubmit, release } = renderWithSlowSubmit()
    const form = document.querySelector('form')

    fireEvent.submit(form)
    expect(onSubmit).toHaveBeenCalledTimes(1)

    release()
    // let the awaited handler's `finally` run before submitting again
    await new Promise((resolve) => setTimeout(resolve, 0))

    fireEvent.submit(form)
    expect(onSubmit).toHaveBeenCalledTimes(2)
  })

  it('still collects the form fields it always collected', () => {
    const onSubmit = vi.fn()
    render(
      <FormModal open onClose={() => {}} title="Create" onSubmit={onSubmit}>
        <input name="label" defaultValue="hello" />
      </FormModal>
    )
    fireEvent.submit(document.querySelector('form'))
    expect(onSubmit).toHaveBeenCalledWith({ label: 'hello' })
  })
})
