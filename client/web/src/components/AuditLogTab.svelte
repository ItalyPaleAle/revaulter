<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'

import { v2AuditEvents } from '$lib/v2-api'
import type { V2AuditEvent } from '$lib/v2-types'

let auditEvents = $state<V2AuditEvent[]>([])
let auditCursor = $state('')
let auditLoading = $state(false)
let auditHasMore = $state(false)
let auditError = $state<string | null>(null)
let loaded = $state(false)
let selectedEventType = $state('')

const eventTypeOptions = [
    'auth.register_finish',
    'auth.finalize_signup',
    'auth.login_finish',
    'auth.logout',
    'auth.request_key_regenerate',
    'auth.allowed_ips_change',
    'auth.display_name_change',
    'auth.wrapped_key_update',
    'auth.credential_add_finish',
    'auth.credential_rename',
    'auth.credential_delete',
    'request.create',
    'request.confirm',
    'request.cancel',
    'request.expire',
    'signing_key.create',
    'signing_key.publish',
    'signing_key.unpublish',
    'signing_key.delete',
    'signing_key.auto_store',
]

$effect(() => {
    if (!loaded && !auditLoading) {
        loaded = true
        void loadAuditEvents()
    }
})

async function loadAuditEvents(cursor?: string) {
    auditLoading = true
    auditError = null
    try {
        const res = await v2AuditEvents({ cursor, eventType: selectedEventType })
        if (cursor) {
            auditEvents = [...auditEvents, ...res.events]
        } else {
            auditEvents = res.events
        }
        auditCursor = res.nextCursor
        auditHasMore = res.nextCursor !== ''
    } catch (err) {
        auditError = err instanceof Error ? err.message : String(err)
    } finally {
        auditLoading = false
    }
}

function handleEventTypeChange(event: Event) {
    const target = event.target as HTMLSelectElement
    selectedEventType = target.value
    auditEvents = []
    auditCursor = ''
    auditHasMore = false
    void loadAuditEvents()
}

function eventTypeLabel(eventType: string): string {
    return eventType.replace(/_/g, ' ').replace(/\./g, ' › ')
}

function auditOutcomeClass(outcome: string): string {
    switch (outcome) {
        case 'success':
            return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300'
        case 'failure':
            return 'bg-rose-100 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300'
        case 'denied':
            return 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300'
        default:
            return 'bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-300'
    }
}

function formatRelativeTimestamp(unix: number): string {
    const date = new Date(unix * 1000)
    if (Number.isNaN(date.getTime())) {
        return 'Unknown'
    }

    return formatDistanceToNowStrict(date, { addSuffix: true })
}

function formatExactTimestamp(unix: number): string {
    const date = new Date(unix * 1000)
    if (Number.isNaN(date.getTime())) {
        return 'Unknown time'
    }

    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short',
    }).format(date)
}

function authMethodLabel(method: string): string {
    switch (method) {
        case 'request_key':
            return 'Request key'
        case 'system':
            return 'System'
        case 'none':
            return 'None'
        default:
            return 'Session'
    }
}

function resourceLabel(entry: V2AuditEvent): string {
    if (entry.requestState) {
        return `Request ${shortenId(entry.requestState)}`
    }
    if (entry.signingKeyId) {
        return `Signing key ${shortenId(entry.signingKeyId)}`
    }
    if (entry.credentialId) {
        return `Passkey ${shortenId(entry.credentialId)}`
    }
    return 'Account'
}

function shortenId(id: string): string {
    if (id.length <= 16) {
        return id
    }
    return `${id.slice(0, 8)}…${id.slice(-8)}`
}
</script>

<div class="space-y-4">
    <div>
        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Audit log</div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Recent actions performed on your account. Entries are retained for 30 days.
        </p>
    </div>

    <div class="flex flex-wrap items-end gap-3">
        <label class="flex min-w-56 flex-col gap-1.5 text-xs font-medium text-neutral-600 dark:text-neutral-300">
            Event
            <select
                class="h-9 rounded-lg border border-neutral-300 bg-white px-3 text-[13px] text-neutral-900 outline-none transition focus:border-neutral-900 focus:ring-2 focus:ring-neutral-200 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-50 dark:focus:border-neutral-300 dark:focus:ring-neutral-800"
                value={selectedEventType}
                onchange={handleEventTypeChange}
                disabled={auditLoading}
            >
                <option value="">All events</option>
                {#each eventTypeOptions as eventType}
                    <option value={eventType}>{eventTypeLabel(eventType)}</option>
                {/each}
            </select>
        </label>
    </div>

    {#if auditError}
        <div class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
            {auditError}
        </div>
    {/if}

    {#if auditEvents.length === 0 && !auditLoading}
        <div class="rounded-lg border border-dashed border-neutral-300 bg-white px-6 py-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
            No audit events found.
        </div>
    {:else if auditEvents.length === 0 && auditLoading}
        <div class="rounded-lg border border-neutral-200 bg-white px-6 py-8 text-center text-sm text-neutral-500 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-400">
            Loading audit events...
        </div>
    {:else}
        <div class="overflow-x-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
            <table class="min-w-full divide-y divide-neutral-200 text-sm dark:divide-neutral-800">
                <thead class="bg-neutral-50 dark:bg-neutral-950/40">
                    <tr>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Date</th>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Event</th>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Resource</th>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Outcome</th>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Auth method</th>
                        <th class="whitespace-nowrap px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">IP</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-neutral-200 bg-white dark:divide-neutral-800 dark:bg-neutral-900">
                    {#each auditEvents as entry (entry.id)}
                        <tr class="transition hover:bg-neutral-50 dark:hover:bg-neutral-800/60">
                            <td class="mono whitespace-nowrap px-4 py-2.5 text-xs text-neutral-600 dark:text-neutral-400">
                                <time datetime={new Date(entry.createdAt * 1000).toISOString()} title={formatExactTimestamp(entry.createdAt)}>
                                    {formatRelativeTimestamp(entry.createdAt)}
                                </time>
                            </td>
                            <td class="whitespace-nowrap px-4 py-2.5 text-xs text-neutral-900 dark:text-neutral-50" title={entry.eventType}>
                                {eventTypeLabel(entry.eventType)}
                            </td>
                            <td class="mono whitespace-nowrap px-4 py-2.5 text-xs text-neutral-600 dark:text-neutral-400" title={entry.requestState || entry.signingKeyId || entry.credentialId || 'Account'}>
                                {resourceLabel(entry)}
                            </td>
                            <td class="whitespace-nowrap px-4 py-2.5">
                                <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium {auditOutcomeClass(entry.outcome)}">
                                    {entry.outcome}
                                </span>
                            </td>
                            <td class="whitespace-nowrap px-4 py-2.5 text-xs text-neutral-600 dark:text-neutral-400">
                                {authMethodLabel(entry.authMethod)}
                            </td>
                            <td class="mono whitespace-nowrap px-4 py-2.5 text-xs text-neutral-600 dark:text-neutral-400" title={entry.userAgent || undefined}>
                                {entry.clientIp || '-'}
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>

        <div class="flex items-center justify-between">
            <div class="text-xs text-neutral-500 dark:text-neutral-400">
                {auditEvents.length} event{auditEvents.length !== 1 ? 's' : ''}
            </div>
            {#if auditHasMore}
                <Button
                    variant="secondary"
                    size="sm"
                    onclick={() => loadAuditEvents(auditCursor)}
                    disabled={auditLoading}
                >
                    {#if auditLoading}
                        <Icon icon="loader" title="Loading" size="3.5" />
                    {:else}
                        <Icon icon="chevron-down" title="Load more" size="3.5" />
                    {/if}
                    Load more
                </Button>
            {/if}
        </div>
    {/if}
</div>
