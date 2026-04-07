<script lang="ts">
import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'

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
</script>

<div class="mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center px-4 py-10 md:px-6">
    <section class="mx-auto flex w-full max-w-md flex-col items-stretch justify-center">
        <div class="rounded-4xl border border-white/80 bg-white/85 p-6 shadow-[0_35px_90px_-45px_rgba(15,23,42,0.55)] backdrop-blur dark:border-slate-800 dark:bg-slate-950/80 md:p-8">
            <div class="mb-6 space-y-3">
                <div class="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 lg:hidden">
                    Revaulter v2
                </div>
                <div class="space-y-2">
                    <h2 class="font-serif text-3xl text-slate-950 dark:text-white">{authHeadline()}</h2>
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
                <div class="flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
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
                    <div class="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-300">
                        Unlocking local keys for <span class="font-mono text-slate-950 dark:text-white">{sessionLabel}</span>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-password-login">Password</label>
                        <input
                            id="v2-password-login"
                            type="password"
                            class="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
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
