<div class="my-2">
    {#if error}
        <p class="p-2 border rounded-xs bg-rose-50 dark:bg-rose-800 text-rose-800 dark:text-white border-rose-700 dark:border-rose-900">{error}</p>
    {/if}
    <div class="flex flex-row">
        <div class="flex-none pt-2 mr-4 w-14 h-14 text-slate-700 dark:text-slate-300">
            <Icon icon={itemUI.icon} title={itemUI.iconTitle} size="14" />
        </div>
        <div class="space-y-2">
            <div class="space-y-0.5">
                <span class="flex flex-row items-center">
                    <span class="flex-none w-6 pr-2"></span>
                    <span class="grow">
                        <b class="text-slate-900 dark:text-white">{item.requestor}</b> wants to <b class="text-slate-900 dark:text-white">{itemUI.action}</b> {itemUI.actionObject}
                    </span>
                </span>
                {#if item.note}
                    <span class="flex flex-row items-center text-sm">
                        <span class="grow-0 w-6 pr-2">
                            <Icon icon="note" title="Note" size={'4'} />
                        </span>
                        <span class="grow">
                            <span class="italic font-semibold text-slate-900 dark:text-white">{item.note}</span>
                        </span>
                    </span>
                {/if}
                <span class="flex flex-row items-center text-sm">
                    <span class="grow-0 w-6 pr-2">
                        <Icon icon="key" title="Vault name and key" size={'4'} />
                    </span>
                    <span class="grow">
                        <b class="text-slate-900 dark:text-white">{item.vaultName}</b> / <b class="text-slate-900 dark:text-white">{item.keyId}</b>
                    </span>
                </span>
                <span class="flex flex-row items-center text-sm">
                    <span class="grow-0 w-6 pr-2">
                        <Icon icon="clock" title="Time of the request (local)" size={'4'} />
                    </span>
                    <span class="grow">
                        <b class="text-slate-900 dark:text-white">{format(item.date * 1000, 'PPpp')}</b>
                    </span>
                </span>
                <span class="flex flex-row items-center text-sm">
                    <span class="grow-0 w-6 pr-2">
                        <Icon icon="data" title="Request ID" size={'4'} />
                    </span>
                    <span class="grow font-mono">
                        {item.state}
                    </span>
                </span>
            </div>
            {#await submitting}
                <p>Working on it...</p>
            {:then _}
                {#if item.status === pendingRequestStatus.pendingRequestRemoved}
                    <p>This request has already been completed or has expired</p>
                {:else if item.status === pendingRequestStatus.pendingRequestConfirmed}
                    <p>Request confirmed</p>
                {:else if item.status === pendingRequestStatus.pendingRequestCanceled}
                    <p>Request canceled</p>
                {:else if item.status === pendingRequestStatus.pendingRequestFailed_Client}
                    <p>Request failed</p>
                {:else if item.status === pendingRequestStatus.pendingRequestProcessing_Client}
                    <p><LoadingSpinner /> Working on it…</p>
                {:else}
                    <div class="flex flex-row">
                        <div role="button"
                            class="flex flex-row items-center flex-auto p-2 m-2 rounded-sm shadow-xs text-emerald-700 dark:text-emerald-400 hover:text-slate-900 dark:hover:text-white bg-slate-200 dark:bg-slate-700 border-emerald-300 dark:border-emerald-600 hover:bg-emerald-300 dark:hover:bg-emerald-600 cursor-pointer"
                            tabindex="-20"
                            on:click={() => submit(true)} on:keypress={() => submit(true)}
                        >
                            <span class="pr-2 w-7">
                                <Icon icon="check-circle" title="" size={'5'} /> 
                            </span>
                            <span>Confirm</span>
                        </div>
                        <div role="button"
                            class="flex flex-row items-center flex-auto p-2 m-2 rounded-sm shadow-xs text-rose-700 dark:text-rose-400 hover:text-slate-900 dark:hover:text-white bg-slate-200 dark:bg-slate-700 border-rose-300 dark:border-rose-600 hover:bg-rose-300 dark:hover:bg-rose-600 cursor-pointer"
                            tabindex="-19"
                            on:click={() => submit(false)} on:keypress={() => submit(false)}
                        >
                            <span class="pr-2 w-7">
                                <Icon icon="x-circle" title="" size={'5'} /> 
                            </span>
                            <span>Cancel</span>
                        </div>
                    </div>
                {/if}
            {/await}
        </div>
    </div>
</div>

<script lang="ts">
import {format} from 'date-fns'

import {Request} from '../lib/request'
import {pendingRequestStatus, type pendingRequestItem, operations} from '../lib/types'

import Icon from './Icon.svelte'
import LoadingSpinner from './LoadingSpinner.svelte'

export let item: pendingRequestItem
$: itemUI = uiForOperation(item.operation)

function uiForOperation(operation: operations) {
    switch (operation) {
        case operations.operationEncrypt:
            return {
                action: 'encrypt',
                actionObject: 'a message',
                icon: 'lock-closed',
                iconTitle: 'Encrypt request'
            }
        case operations.operationDecrypt:
            return {
                action: 'decrypt',
                actionObject: 'a message',
                icon: 'lock-open',
                iconTitle: 'Decrypt request'
            }
        case operations.operationSign:
            return {
                action: 'sign',
                actionObject: 'a message',
                icon: 'pencil',
                iconTitle: 'Sign request'
            }
        case operations.operationVerify:
            return {
                action: 'verify',
                actionObject: 'a signature',
                icon: 'check-badge',
                iconTitle: 'Verify request'
            }
        case operations.operationWrap:
            return {
                action: 'wrap',
                actionObject: 'a key',
                icon: 'lock-closed',
                iconTitle: 'Wrap request'
            }
        case operations.operationUnwrap:
            return {
                action: 'unwrap',
                actionObject: 'a key',
                icon: 'lock-open',
                iconTitle: 'Unwrap request'
            }
    }
}

let submitting: Promise<void> = Promise.resolve()
let error: string|null = null
export function submit(confirm: boolean) {
    // Request body
    const body: {
        state: string
        confirm?: boolean
        cancel?: boolean
    } = {
        state: item.state
    }
    if (confirm) {
        body.confirm = true
    } else {
        body.cancel = true
    }

    // Make the request as processing in the client, so its status won't be changed to "removed" by the server
    item.status = pendingRequestStatus.pendingRequestProcessing_Client

    submitting = Promise.resolve()
        .then(() => Request<{confirmed?: boolean, canceled?: boolean}>('/api/confirm', {
            postData: body,
            // Set timeout to 60s as this operation can take longer
            timeout: 60000
        }))
        .then((res) => {
            if (confirm) {
                if (res?.data?.confirmed !== true) {
                    throw Error('The operation was not confirmed')
                }
                item.status = pendingRequestStatus.pendingRequestConfirmed
            } else {
                if (res?.data?.canceled !== true) {
                    throw Error('The operation was not canceled')
                }
                item.status = pendingRequestStatus.pendingRequestCanceled
            }
            item = item
        })
        .catch((err) => {
            // eslint-disable-next-line
            error = (err && typeof err.toString == 'function') ? err.toString() : ''
            item.status = pendingRequestStatus.pendingRequestFailed_Client
        })
}
</script>