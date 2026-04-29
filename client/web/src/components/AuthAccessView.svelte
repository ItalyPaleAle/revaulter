<script lang="ts">
import { tick } from 'svelte'
import heroImage from '$assets/hero.avif'
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import Logo from '$components/Logo.svelte'
import TextField from '$components/TextField.svelte'

interface Props {
    authBusy: boolean
    authError: string | null
    loginWrappedPrimaryKey: string | null
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
    loginWrappedPrimaryKey,
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
    return 'Sign in to Revaulter'
}

function authBodyCopy() {
    if (uiState === 'password-login') {
        return 'Your session is active. Enter the password to unlock local cryptographic operations in this browser.'
    }
    return 'Authenticate with your passkey to access pending operations.'
}

$effect(() => {
    if (uiState !== 'password-login' || !loginWrappedPrimaryKey) {
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

<div class="grid min-h-screen grid-cols-1 lg:grid-cols-2">
    <!-- Left pane: sign-in form -->
    <div class="flex min-h-screen items-center justify-center px-6 py-12">
        <div class="w-full max-w-90">
            <div class="mb-8">
                <Logo size={48} />
            </div>

            <h1 class="mb-2 text-[30px] font-semibold leading-tight tracking-tight text-neutral-950 dark:text-neutral-50">
                {authHeadline()}
            </h1>
            <p class="mb-8 text-[15px] leading-6 text-neutral-500 dark:text-neutral-400">
                {authBodyCopy()}
            </p>

            {#if pageError}
                <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {pageError}
                </div>
            {/if}

            {#if authError}
                <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {authError}
                </div>
            {/if}

            {#if uiState === 'boot'}
                <div class="flex items-center gap-3 text-sm text-neutral-600 dark:text-neutral-300">
                    <LoadingSpinner size="1rem" />
                    Initializing…
                </div>
            {:else if uiState === 'password-login' && loginWrappedPrimaryKey}
                <form
                    class="space-y-4"
                    onsubmit={(event) => {
                        event.preventDefault()
                        if (!authBusy) {
                            void onFinishPasswordLogin()
                        }
                    }}
                >
                    <div class="rounded-lg border border-neutral-200 bg-neutral-50 px-3.5 py-2.5 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">
                        Unlocking local keys for <span class="mono font-medium text-neutral-900 dark:text-neutral-50">{sessionLabel}</span>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-neutral-900 dark:text-neutral-100" for="password-login">Password</label>
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

                <div class="mt-8 border-t border-neutral-200 pt-6 dark:border-neutral-800">
                    <button
                        type="button"
                        class="cursor-pointer text-sm text-neutral-500 underline decoration-neutral-300 underline-offset-4 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:decoration-neutral-700 dark:hover:text-neutral-50"
                        onclick={() => {
                            void onReturnToSignIn()
                        }}
                    >
                        Back to sign in
                    </button>
                </div>
            {:else}
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
                    {#if authBusy}
                        <LoadingSpinner size="1rem" />
                        Authenticating…
                    {:else}
                        <Icon icon="key" title="Passkey" size="4" />
                        Continue with passkey
                    {/if}
                </Button>

                {#if signupDisabled}
                    <div class="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-sm text-amber-800 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-200">
                        Account creation is disabled on this server.
                    </div>
                {:else}
                    <div class="mt-8 border-t border-neutral-200 pt-6 dark:border-neutral-800">
                        <button
                            type="button"
                            class="cursor-pointer text-sm text-neutral-500 underline decoration-neutral-300 underline-offset-4 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:decoration-neutral-700 dark:hover:text-neutral-50"
                            onclick={onOpenSignup}
                        >
                            Create a new account
                        </button>
                    </div>
                {/if}
            {/if}
        </div>
    </div>

    <!-- Right pane: hero image -->
    <div class="hidden p-4 lg:block">
        <div
            class="relative h-[calc(100vh-2rem)] w-full overflow-hidden rounded-[20px] border border-neutral-200 bg-cover bg-center dark:border-neutral-800"
            style={`background-image: url(${heroImage});`}
        >
            <div class="pointer-events-none absolute inset-0 rounded-[20px] ring-1 ring-inset ring-black/5"></div>
        </div>
    </div>
</div>
