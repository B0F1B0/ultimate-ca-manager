import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CloudArrowUp, Plus, Trash, UploadSimple } from '@phosphor-icons/react'
import { Badge, Button, CompactSection } from './index'
import { Modal } from './Modal'
import { deployService } from '../services'
import { useNotification } from '../contexts'
import { usePermission } from '../hooks'
import { extractData } from '../lib/utils'

const EMPTY = {
  target_id: '', crl_path: '/root/certs/CRL.crl', format: 'pem',
  include_parent_crls: true, enabled: true,
}

export function CRLDeploySection({ ca, hasCRL }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermission()
  const { showSuccess, showError, showConfirm } = useNotification()
  const [bindings, setBindings] = useState([])
  const [targets, setTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [deploying, setDeploying] = useState(null)
  const [form, setForm] = useState(EMPTY)
  const canReadDeploy = hasPermission('read:deploy')
  const canWriteDeploy = hasPermission('write:deploy')
  const canDeleteDeploy = hasPermission('delete:deploy')

  const load = useCallback(async () => {
    if (!ca?.id || !canReadDeploy) return
    setLoading(true)
    try {
      const [bindingRes, targetRes] = await Promise.all([
        deployService.getCRLBindings({ ca_id: ca.id }),
        deployService.getTargets(),
      ])
      setBindings(extractData(bindingRes) || [])
      setTargets((extractData(targetRes) || []).filter(target => target.enabled))
    } catch (error) {
      showError(error.message || t('crlDeploy.loadFailed', 'Failed to load CRL deployments'))
    } finally {
      setLoading(false)
    }
  }, [ca?.id, canReadDeploy, showError, t])

  useEffect(() => { load() }, [load])

  const create = async (event) => {
    event.preventDefault()
    setSaving(true)
    try {
      await deployService.createCRLBinding({
        ...form, target_id: Number(form.target_id), ca_id: ca.id,
      })
      showSuccess(t('crlDeploy.created', 'CRL deployment attached and initial push queued'))
      setOpen(false)
      setForm(EMPTY)
      await load()
    } catch (error) {
      showError(error.message || t('crlDeploy.createFailed', 'Failed to attach CRL deployment'))
    } finally {
      setSaving(false)
    }
  }

  const remove = async (binding) => {
    const confirmed = await showConfirm(
      t('crlDeploy.deleteConfirm', 'Remove this CRL deployment?'),
      { title: t('crlDeploy.remove', 'Remove CRL deployment'), variant: 'danger' })
    if (!confirmed) return
    try {
      await deployService.deleteCRLBinding(binding.id)
      showSuccess(t('crlDeploy.removed', 'CRL deployment removed'))
      await load()
    } catch (error) {
      showError(error.message || t('crlDeploy.deleteFailed', 'Failed to remove CRL deployment'))
    }
  }

  const deployNow = async (binding) => {
    setDeploying(binding.id)
    try {
      await deployService.deployCRLNow(binding.id)
      showSuccess(t('crlDeploy.deployed', 'CRL deployed successfully'))
      await load()
    } catch (error) {
      showError(error.message || t('crlDeploy.deployFailed', 'CRL deployment failed'))
    } finally {
      setDeploying(null)
    }
  }

  const availableTargets = targets.filter(
    target => !bindings.some(binding => binding.target_id === target.id))

  if (!canReadDeploy) return null

  return (
    <>
      <CompactSection title={t('crlDeploy.title', 'CRL deployment')} icon={CloudArrowUp}>
        <p className="text-xs text-text-tertiary mb-3">
          {t('crlDeploy.description', 'Push every updated complete CRL to an SSH deployment target.')}
        </p>
        {loading ? (
          <div className="text-xs text-text-tertiary">{t('common.loading')}</div>
        ) : bindings.length === 0 ? (
          <p className="text-xs text-text-tertiary italic">
            {t('crlDeploy.none', 'This CA is not deployed to any target.')}
          </p>
        ) : (
          <div className="space-y-2">
            {bindings.map(binding => (
              <div key={binding.id} className="p-2 rounded-md bg-bg-tertiary border border-border">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-text-primary truncate">
                        {binding.target_name}
                      </span>
                      <Badge variant={binding.last_delivery?.status === 'failed' ? 'danger' : 'success'} size="sm">
                        {binding.last_delivery?.status || t('common.enabled')}
                      </Badge>
                    </div>
                    <code className="block text-xs text-text-secondary break-all mt-1">
                      {binding.crl_path}
                    </code>
                    <p className="text-xs text-text-tertiary mt-1">
                      {binding.format.toUpperCase()}
                      {binding.include_parent_crls
                        ? ` · ${t('crlDeploy.withParents', 'includes parent CRLs')}` : ''}
                    </p>
                  </div>
                  {(canWriteDeploy || canDeleteDeploy) && (
                    <div className="flex gap-1 shrink-0">
                      {canWriteDeploy && (
                        <Button type="button" size="xs" variant="secondary"
                          onClick={() => deployNow(binding)} disabled={deploying === binding.id}
                          title={t('crlDeploy.deployNow', 'Deploy now')}>
                          <UploadSimple size={14} />
                        </Button>
                      )}
                      {canDeleteDeploy && (
                        <Button type="button" size="xs" variant="ghost"
                          onClick={() => remove(binding)} title={t('common.remove')}>
                          <Trash size={14} />
                        </Button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
        {canWriteDeploy && hasCRL && (
          <Button type="button" size="sm" variant="secondary" className="mt-3"
            onClick={() => { setForm(EMPTY); setOpen(true) }}
            disabled={availableTargets.length === 0}>
            <Plus size={14} /> {t('crlDeploy.attach', 'Attach target')}
          </Button>
        )}
      </CompactSection>

      <Modal open={open} onOpenChange={value => !saving && setOpen(value)}
        title={t('crlDeploy.attachFor', 'Attach CRL target: {{name}}', { name: ca?.descr || ca?.name })}
        size="sm">
        <form onSubmit={create} className="p-4 space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">
              {t('deploy.target', 'Target')}
            </label>
            <select required value={form.target_id}
              onChange={event => setForm({ ...form, target_id: event.target.value })}
              className="w-full rounded-md border border-border bg-bg-primary text-text-primary text-sm p-2">
              <option value="">{t('deploy.selectTarget', 'Select a target...')}</option>
              {availableTargets.map(target => (
                <option key={target.id} value={target.id}>{target.name} ({target.host})</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">
              {t('crlDeploy.path', 'CRL destination path')}
            </label>
            <input required value={form.crl_path}
              onChange={event => setForm({ ...form, crl_path: event.target.value })}
              className="w-full rounded-md border border-border bg-bg-primary text-text-primary text-sm font-mono p-2"
              placeholder="/root/certs/CRL.crl" />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">
              {t('common.format', 'Format')}
            </label>
            <select value={form.format}
              onChange={event => setForm({
                ...form, format: event.target.value,
                include_parent_crls: event.target.value === 'pem' && form.include_parent_crls,
              })}
              className="w-full rounded-md border border-border bg-bg-primary text-text-primary text-sm p-2">
              <option value="pem">PEM</option>
              <option value="der">DER</option>
            </select>
          </div>
          <label className="flex items-start gap-2 rounded-md border border-border p-3">
            <input type="checkbox" className="mt-0.5" checked={form.include_parent_crls}
              disabled={form.format !== 'pem'}
              onChange={event => setForm({ ...form, include_parent_crls: event.target.checked })} />
            <span>
              <span className="block text-sm font-medium text-text-primary">
                {t('crlDeploy.includeParents', 'Include parent CRLs')}
              </span>
              <span className="block text-xs text-text-tertiary">
                {t('crlDeploy.includeParentsHelp', 'Creates a PEM bundle containing this CA CRL followed by issuer CRLs.')}
              </span>
            </span>
          </label>
          <div className="flex justify-end gap-2 pt-2 border-t border-border">
            <Button type="button" variant="secondary" onClick={() => setOpen(false)} disabled={saving}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={saving || !form.target_id}>
              {t('crlDeploy.attach', 'Attach target')}
            </Button>
          </div>
        </form>
      </Modal>
    </>
  )
}
