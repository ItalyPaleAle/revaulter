<script lang="ts">
import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import TextField from '$components/TextField.svelte'

interface Props {
    authBusy: boolean
    authError: string | null
    displayName: string
    onDisplayNameInput: (value: string) => void
    onPasswordInput: (value: string) => void
    onRegister: () => Promise<void>
    onReturnToSignIn: () => Promise<void>
    onSetPassword: () => Promise<void>
    onSkipPassword: () => void
    pageError: string | null
    passwordInput: string
    uiState: 'signup' | 'password-setup'
}

let {
    authBusy,
    authError,
    displayName,
    onDisplayNameInput,
    onPasswordInput,
    onRegister,
    onReturnToSignIn,
    onSetPassword,
    onSkipPassword,
    pageError,
    passwordInput,
    uiState,
}: Props = $props()

function authHeadline() {
    if (uiState === 'signup') {
        return 'Create a new account'
    }
    return 'Add a password'
}

function authBodyCopy() {
    if (uiState === 'signup') {
        return 'Register a new Revaulter user with a resident passkey. You can add an optional password after registration.'
    }
    return 'Passwords are optional. If you set one now, Revaulter will ask for it after future passkey sign-ins before unlocking local keys.'
}
</script>

<div class="mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center px-4 py-10 md:px-6">
    <section class="mx-auto flex w-full max-w-md flex-col items-stretch justify-center">
        <div class="rounded-4xl border border-white/85 bg-white/92 p-6 shadow-[0_8px_24px_-20px_rgba(15,23,42,0.22)] dark:border-white/10 dark:bg-slate-950/88 md:p-8">
            <div class="relative mb-6 space-y-3">
                <div class="inline-flex items-center rounded-full bg-white/60 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500 ring-1 ring-slate-200/70 dark:bg-white/6 dark:text-slate-300 dark:ring-white/10 lg:hidden">
                    Revaulter v2
                </div>
                <div class="space-y-2">
                    <h2 class="text-3xl text-slate-950 dark:text-white" data-display="serif">{authHeadline()}</h2>
                    <p class="text-sm leading-6 text-slate-600 dark:text-slate-300">{authBodyCopy()}</p>
                </div>
            </div>

            {#if pageError}
                <div class="mb-4 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {pageError}
                </div>
            {/if}

            {#if authError}
                <div class="mb-4 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {authError}
                </div>
            {/if}

            {#if uiState === 'signup'}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            void onRegister()
                        }
                    }}
                >
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-displayname">Display name (optional)</label>
                        <TextField
                            id="v2-displayname"
                            value={displayName}
                            oninput={(event) => {
                                onDisplayNameInput((event.currentTarget as HTMLInputElement).value)
                            }}
                        />
                    </div>

                    <Button
                        type="submit"
                        variant="neutral"
                        size="lg"
                        width="full"
                        disabled={authBusy}
                    >
                        {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                        Create account with passkey
                    </Button>
                </form>
            {:else}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            void onSetPassword()
                        }
                    }}
                >
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-password-setup">Password</label>
                        <TextField
                            id="v2-password-setup"
                            type="password"
                            value={passwordInput}
                            oninput={(event) => {
                                onPasswordInput((event.currentTarget as HTMLInputElement).value)
                            }}
                        />
                    </div>

                    <div class="flex flex-col gap-3 sm:flex-row">
                        <Button
                            type="submit"
                            class="flex-1"
                            variant="primary"
                            size="lg"
                            disabled={authBusy}
                        >
                            {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                            Save password
                        </Button>
                        <Button
                            type="button"
                            class="flex-1"
                            variant="outline"
                            size="lg"
                            onclick={onSkipPassword}
                        >
                            Skip password
                        </Button>
                    </div>
                </form>
            {/if}
        </div>

        <Button
            type="button"
            class="mt-4"
            variant="surface"
            size="lg"
            onclick={() => {
                void onReturnToSignIn()
            }}
        >
            Back to sign in
        </Button>
    </section>
</div>
