<div class="max-w-screen-md px-6 py-4 mx-auto my-4">
    {#if sessionExpired}
        <h1 class="text-lg font-medium text-slate-900 dark:text-white">Your session has expired</h1>
        <div class="px-6 py-4 mx-auto my-4 bg-white rounded-lg shadow-lg dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
            <button class="p-2 m-2 rounded shadow-sm bg-slate-200 dark:bg-slate-700 border-slate-300 dark:border-slate-600 hover:bg-slate-300 hover:dark:bg-slate-600" on:click={() => window.location.reload()}>Reload page</button>
        </div>
    {:else}
        <List on:sessionExpired={setSessionExpired} />
    {/if}
</div>

<script lang="ts">
import List from './components/List.svelte'

let sessionExpired = false

function setSessionExpired(event: CustomEvent<boolean>) {
    sessionExpired = event.detail
}
</script>
