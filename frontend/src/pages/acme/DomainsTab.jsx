import { useTranslation } from 'react-i18next'
import { Plus, Trash, Play, Gear, PlugsConnected, GlobeHemisphereWest } from '@phosphor-icons/react'
import { Button, Badge, Card, HelpCard, ResponsiveDataTable } from '../../components'

export default function DomainsTab({ acmeDomains, dnsProviders, cas, onAdd, onEdit, onDelete, onTest, canWrite, canDelete }) {
  const { t } = useTranslation()

  return (
    <div className="space-y-4">
      <HelpCard variant="info" title={t('acme.domainsHelp')} compact>
        {t('acme.domainsHelpDesc')}
      </HelpCard>

      {acmeDomains.length === 0 ? (
        <Card className="p-8 text-center">
          <GlobeHemisphereWest size={48} className="mx-auto text-text-tertiary mb-4" />
          <h3 className="text-lg font-medium text-text-primary mb-2">
            {t('acme.noDomainsYet')}
          </h3>
          <p className="text-sm text-text-secondary mb-4">
            {t('acme.noDomainsDesc')}
          </p>
          {canWrite && (
            <Button type="button" onClick={onAdd}>
              <Plus size={14} />
              {t('acme.addDomain')}
            </Button>
          )}
        </Card>
      ) : (
        <ResponsiveDataTable
          data={acmeDomains}
          columns={[
            {
              key: 'domain',
              priority: 1,  // card view: what identifies the row
              size: 3,  // a domain name can be long
              label: t('acme.domain'),
              sortable: true,
              render: (val) => (
                <span className="font-mono text-sm">{val}</span>
              )
            },
            {
              key: 'dns_provider_name',
              priority: 2,  // card view: what tells two domains apart
              size: 2,  // a short provider name
              label: t('acme.provider'),
              sortable: true,
              render: (val, row) => (
                <div className="flex items-center gap-2">
                  <PlugsConnected size={14} className="text-accent-primary" />
                  <span>{val || row.dns_provider_type}</span>
                </div>
              )
            },
            {
              key: 'issuing_ca_name',
              priority: 4,  // card view: usually 'Default', table only
              size: 2.5,  // a CA name, or 'Default'
              label: t('acme.issuingCA'),
              sortable: true,
              render: (val) => (
                <span className={val ? 'text-text-primary' : 'text-text-tertiary'}>
                  {val || t('acme.defaultCA')}
                </span>
              )
            },
            {
              key: 'is_wildcard_allowed',
              priority: 5,  // card view: table only
              width: '92px',  // a Yes/No badge under an 8-letter header
              label: t('acme.wildcard'),
              render: (val) => (
                <Badge variant={val ? 'success' : 'secondary'}>
                  {val ? t('common.yes') : t('common.no')}
                </Badge>
              )
            },
            {
              key: 'auto_approve',
              priority: 3,  // card view: the state worth seeing at a glance
              width: '116px',  // a short badge under a 12-letter header
              label: t('acme.autoApprove'),
              render: (val) => (
                <Badge variant={val ? 'success' : 'warning'}>
                  {val ? t('common.auto') : t('common.manual')}
                </Badge>
              )
            },
          ]}
          rowActions={(row) => [
            { label: t('acme.testDnsAccess'), icon: Play, onClick: () => onTest(row) },
            ...(canWrite ? [{ label: t('common.edit'), icon: Gear, onClick: () => onEdit(row) }] : []),
            ...(canDelete ? [{ label: t('common.delete'), icon: Trash, variant: 'danger', onClick: () => onDelete(row) }] : []),
          ]}
          onRowClick={(row) => onEdit(row)}
          emptyMessage={t('acme.noDomains')}
        />
      )}
    </div>
  )
}
