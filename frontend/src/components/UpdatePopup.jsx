/**
 * UpdatePopup — optional "what's new" window shown once per user after an
 * update was installed (#308).
 *
 * Server side: the admin enables it in Settings › Updates (off by default,
 * `popup_enabled` in the update settings). Per user: the last acknowledged
 * version lives in the server-side preferences (`update_popup_seen_version`),
 * so dismissing it on one browser dismisses it everywhere.
 */
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import ReactMarkdown from 'react-markdown'
import { Rocket } from '@phosphor-icons/react'
import { Modal } from './Modal'
import { Button } from './Button'
import { apiClient } from '../services'
import { useAuth } from '../contexts/AuthContext'
import { getPreferences, persistPreference } from '../stores/userPreferencesStore'
import { formatDate } from '../lib/utils'
import { MARKDOWN_ELEMENT_CLASSES } from '../lib/markdown'

export function UpdatePopup() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [info, setInfo] = useState(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!user) {
      setOpen(false)
      setInfo(null)
      return
    }
    let cancelled = false
    apiClient.get('/system/updates/whatsnew')
      .then((response) => {
        if (cancelled) return
        const data = response?.data || response || {}
        if (!data.enabled || !data.version) return
        if (data.baseline_version === data.version) return
        if (getPreferences().update_popup_seen_version === data.version) return
        setInfo(data)
        setOpen(true)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [user?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const dismiss = () => {
    setOpen(false)
    if (info?.version) persistPreference('update_popup_seen_version', info.version)
  }

  if (!info) return null

  return (
    <Modal
      open={open}
      onClose={dismiss}
      size="lg"
      title={(
        <span className="flex items-center gap-2">
          <Rocket size={18} className="text-accent-primary" />
          {t('updatePopup.title', { version: info.version })}
        </span>
      )}
    >
      <div className="space-y-3">
        {info.installed_at && (
          <p className="text-sm text-text-tertiary">
            {t('updatePopup.installedOn', { date: formatDate(info.installed_at) })}
          </p>
        )}
        {info.release_notes ? (
          <div className={'p-3 bg-tertiary-op50 rounded-lg text-sm text-text-secondary max-h-80 overflow-y-auto prose prose-sm prose-invert max-w-none ' + MARKDOWN_ELEMENT_CLASSES}>
            <ReactMarkdown>{info.release_notes}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-sm text-text-secondary">{t('updatePopup.noNotes')}</p>
        )}
        <div className="flex justify-end pt-2">
          <Button type="button" variant="primary" onClick={dismiss}>
            {t('common.close')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
