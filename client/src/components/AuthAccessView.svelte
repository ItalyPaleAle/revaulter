<script lang="ts">
import { tick } from 'svelte'

import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import TextField from '$components/TextField.svelte'

interface Props {
    authBusy: boolean
    authError: string | null
    loginPasswordCanary: string | null
    onFinishPasswordLogin: () => Promise<void>
    onLogin: () => Promise<void>
    onOpenSignup: () => void
    onPasswordInput: (value: string) => void
    onReturnToSignIn: () => Promise<void>
    pageError: string | null
    passwordInput: string
    sessionLabel: string
    signupDisabled: boolean
    uiState: 'boot' | 'signin' | 'password-login'
}

let {
    authBusy,
    authError,
    loginPasswordCanary,
    onFinishPasswordLogin,
    onLogin,
    onOpenSignup,
    onPasswordInput,
    onReturnToSignIn,
    pageError,
    passwordInput,
    sessionLabel,
    signupDisabled,
    uiState,
}: Props = $props()

function authHeadline() {
    if (uiState === 'password-login') {
        return 'Unlock with your password'
    }
    return 'Sign in with your passkey'
}

function authBodyCopy() {
    if (uiState === 'password-login') {
        return 'Your session is active. Enter the password to unlock local cryptographic operations in this browser.'
    }
    return ''
}

$effect(() => {
    if (uiState !== 'password-login' || !loginPasswordCanary) {
        return
    }

    void (async () => {
        await tick()
        const element = document.getElementById('password-login')
        if (element instanceof HTMLInputElement) {
            element.focus()
        }
    })()
})
</script>

<div class="mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center px-4 py-10 md:px-6">
    <section class="mx-auto flex w-full max-w-md flex-col items-stretch justify-center">
        <div class="relative overflow-hidden rounded-[2rem] border border-white/65 bg-white/50 p-6 shadow-[0_8px_24px_-20px_rgba(15,23,42,0.22)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/48 md:p-8">
            <div class="pointer-events-none absolute inset-x-0 top-0 h-24 bg-[linear-gradient(90deg,rgba(251,191,36,0.2),rgba(14,165,233,0.16),rgba(244,114,182,0.16))] opacity-80 blur-2xl dark:opacity-60"></div>
            <div class="relative mb-6 space-y-3">
                <div class="inline-flex items-center rounded-full bg-white/60 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500 ring-1 ring-slate-200/70 dark:bg-white/6 dark:text-slate-300 dark:ring-white/10 lg:hidden">
                    Revaulter v2
                </div>
                <div class="space-y-2">
                    <h2 class="text-3xl text-slate-950 dark:text-white" data-display="serif">{authHeadline()}</h2>
                    {#if authBodyCopy()}
                        <p class="text-sm leading-6 text-slate-600 dark:text-slate-300">{authBodyCopy()}</p>
                    {/if}
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

            {#if uiState === 'boot'}
                <div class="flex items-center gap-3 border-t border-slate-200/80 px-1 py-4 text-sm text-slate-700 dark:border-white/10 dark:text-slate-200">
                    <LoadingSpinner size="1rem" />
                    Initializing…
                </div>
            {:else if uiState === 'password-login' && loginPasswordCanary}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            void onFinishPasswordLogin()
                        }
                    }}
                >
                    <div class="border-l-2 border-sky-400/80 bg-white/35 px-4 py-3 text-sm text-slate-600 dark:border-sky-300/70 dark:bg-white/4 dark:text-slate-300">
                        Unlocking local keys for <span class="font-mono text-slate-950 dark:text-white">{sessionLabel}</span>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="password-login">Password</label>
                        <TextField
                            id="password-login"
                            type="password"
                            value={passwordInput}
                            oninput={(event) => {
                                onPasswordInput((event.currentTarget as HTMLInputElement).value)
                            }}
                            required
                        />
                    </div>

                    <Button
                        type="submit"
                        variant="primary"
                        size="lg"
                        width="full"
                        disabled={authBusy}
                    >
                        {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                        Unlock local keys
                    </Button>
                </form>
            {:else}
                <div class="space-y-4">
                    <Button
                        type="button"
                        variant="primary"
                        size="lg"
                        width="full"
                        disabled={authBusy}
                        onclick={() => {
                            if (!authBusy) {
                                void onLogin()
                            }
                        }}
                    >
                        {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                        Continue with passkey
                    </Button>

                    {#if signupDisabled}
                        <div class="rounded-2xl border border-amber-200 bg-amber-50/90 px-4 py-3 text-sm text-amber-800 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-200">
                            Account creation is disabled on this server.
                        </div>
                    {/if}
                </div>
            {/if}
        </div>

        {#if uiState === 'signin' && !signupDisabled}
            <Button
                type="button"
                class="mt-4"
                variant="surface"
                size="lg"
                onclick={onOpenSignup}
            >
                Create a new account
            </Button>
        {:else if uiState !== 'signin'}
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
        {/if}
    </section>
</div>
