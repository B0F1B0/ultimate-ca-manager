/**
 * UploadCRLModal — install an externally-generated CRL on a key-less/offline
 * CA (#302). The CRL is signed next to the offline key, validated here
 * (issuer, signature, monotonicity) and served at the CA's CDP endpoint.
 * Accepts pasted PEM or an uploaded file (PEM/DER).
 */
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ListChecks, UploadSimple, Warning } from '@phosphor-icons/react'
import { Modal } from '../../components/Modal'
import { Button } from '../../components/Button'
import { casService } from '../../services'
import { useNotification } from '../../contexts'

const MAX_FILE_SIZE = 5 * 1024 * 1024

export function UploadCRLModal({ open, onClose, ca, onSuccess }) {
  const { t } = useTranslation()
  const { showSuccess, showError } = useNotification()

  const [pemContent, setPemContent] = useState('')
  const [crlFile, setCrlFile] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const fileTooLarge = crlFile && crlFile.size > MAX_FILE_SIZE
  const canSubmit = !submitting && !fileTooLarge && (crlFile || pemContent.trim().length > 0)

  const reset = () => {
    setPemContent('')
    setCrlFile(null)
    setSubmitting(false)
  }

  const handleClose = () => {
    if (submitting) return
    reset()
    onClose?.()
  }

  const handleSubmit = async (e) => {
    e?.preventDefault?.()
    if (!canSubmit) return
    setSubmitting(true)
    try {
      await casService.uploadCrl(ca.id, {
        pemContent: crlFile ? undefined : pemContent.trim(),
        file: crlFile || undefined,
      })
      showSuccess(t('cas.crlInstalled'))
      window.dispatchEvent(new CustomEvent('ucm:data-changed', { detail: { type: 'ca' } }))
      onSuccess?.()
      reset()
      onClose?.()
    } catch (err) {
      showError(err?.message || t('cas.crlInstallFailed'))
      setSubmitting(false)
    }
  }

  const title = useMemo(
    () => `${t('cas.uploadCrlTitle')}: ${ca?.common_name || ca?.descr || `CA #${ca?.id}`}`,
    [t, ca]
  )

  return (
    <Modal open={open} onOpenChange={(v) => !v && handleClose()} title={title} size="md">
      <form onSubmit={handleSubmit} className="p-4 space-y-4">
        <div className="flex items-start gap-3 p-3 rounded-md bg-accent-primary-op10 border border-accent-primary-op30">
          <ListChecks size={20} className="text-accent-primary shrink-0 mt-0.5" />
          <p className="text-xs text-text-secondary">{t('cas.uploadCrlHint')}</p>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-text-secondary">
            {t('cas.uploadCrlPaste')}
          </label>
          <textarea
            className="w-full h-36 px-3 py-2 bg-bg-tertiary border border-border rounded-md text-xs font-mono text-text-primary resize-y focus:outline-none focus:border-accent-primary"
            placeholder="-----BEGIN X509 CRL-----"
            value={pemContent}
            onChange={(e) => { setPemContent(e.target.value); if (e.target.value) setCrlFile(null) }}
            spellCheck={false}
          />
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="ucm-ca-crl-file"
            className="flex items-center gap-2 px-3 py-2 bg-bg-tertiary border border-border rounded-md cursor-pointer hover:border-text-tertiary transition-colors"
          >
            <UploadSimple size={16} className="text-text-tertiary" />
            <span className="text-sm text-text-primary truncate">
              {crlFile ? crlFile.name : t('cas.uploadCrlPick')}
            </span>
          </label>
          <input
            id="ucm-ca-crl-file"
            type="file"
            accept=".crl,.pem,.der,application/pkix-crl,application/x-pem-file"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0] || null
              setCrlFile(f)
              if (f) setPemContent('')
            }}
          />
          {fileTooLarge && (
            <p className="text-xs status-danger-text flex items-center gap-1">
              <Warning size={12} /> {t('cas.uploadCrlTooLarge')}
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-3 border-t border-border">
          <Button type="button" variant="secondary" onClick={handleClose} disabled={submitting}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" loading={submitting} disabled={!canSubmit}>
            {t('cas.uploadCrl')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
