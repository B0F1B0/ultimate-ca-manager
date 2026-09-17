import { useTranslation } from 'react-i18next'
import { Plus, Trash, PencilSimple, GlobeHemisphereWest } from '@phosphor-icons/react'
import { Button, Badge, ResponsiveDataTable } from '../../components'

export default function LocalDomainsTab({ localDomains, cas, onAdd, onEdit, onDelete, canWrite, canDelete }) {
  const { t } = useTranslation()

  return (
    <ResponsiveDataTable
      data={localDomains}
      columns={[
        {
          key: 'domain',
          label: t('acme.domain'),
          sortable: true,
          render: (val) => (
            <span className="font-mono text-sm">{val}</span>
          )
        },
        {
          key: 'issuing_ca_name',
          label: t('acme.issuingCA'),
          sortable: true,
          render: (val) => (
            <span className="text-text-primary">{val || '-'}</span>
          )
        },
        {
          key: 'auto_approve',
          label: t('acme.autoApprove'),
          render: (val) => (
            <Badge variant={val ? 'success' : 'warning'}>
              {val ? t('common.auto') : t('common.manual')}
            </Badge>
          )
        },
      ]}
      rowActions={(row) => [
        ...(canWrite ? [{ label: t('common.edit'), icon: PencilSimple, onClick: () => onEdit(row) }] : []),
        ...(canDelete ? [{ label: t('common.delete'), icon: Trash, variant: 'danger', onClick: () => onDelete(row) }] : []),
      ]}
      emptyState={{
        icon: GlobeHemisphereWest,
        title: t('acme.noLocalDomains'),
        description: t('acme.noLocalDomainsDesc'),
        action: canWrite ? (
          <Button type="button" onClick={onAdd}>
            <Plus size={14} />
            {t('acme.addDomain')}
          </Button>
        ) : null
      }}
      onRowClick={(row) => onEdit(row)}
    />
  )
}
