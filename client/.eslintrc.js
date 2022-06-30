/* eslint-disable quote-props */

const tsParserOptions = {
    tsconfigRootDir: __dirname,
    project: ['./tsconfig.json']
}

const tsExtends = [
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking'
]

module.exports = {
    root: true,
    env: {
        es2019: true,
        node: true,
        browser: true
    },
    extends: [
        'eslint:recommended',
    ],
    parser: '@typescript-eslint/parser',
    parserOptions: {
        ecmaVersion: 2019,
        sourceType: 'module',
    },
    plugins: [
        'html',
        'svelte3',
        '@typescript-eslint'
    ],
    overrides: [
        {
            files: ['*.svelte'],
            processor: 'svelte3/svelte3',
            extends: tsExtends,
            parserOptions: {
                ...tsParserOptions,
                extraFileExtensions: ['.svelte']
            }
        },
        {
            files: ['*.ts'],
            extends: tsExtends,
            parserOptions: tsParserOptions
        }
    ],
    settings: {
        'svelte3/typescript': require('typescript'),
        'svelte3/ignore-styles': () => true,
        'html': {
            'indent': 0,
            'report-bad-indent': 'warn',
            'html-extensions': [
                '.html'
            ]
        }
    },
    rules: {
        'indent': [
            'error',
            4,
            {
                SwitchCase: 1,
                MemberExpression: 1,
                ArrayExpression: 1,
                ObjectExpression: 1
            }
        ],
        'linebreak-style': [
            'error',
            'unix'
        ],
        'quotes': [
            'error',
            'single',
            {
                avoidEscape: true,
                allowTemplateLiterals: true
            }
        ],
        'semi': [
            'error',
            'never'
        ],
        'quote-props': [
            'warn',
            'as-needed'
        ],
        'no-var': [
            'error'
        ],
        'prefer-const': [
            'warn'
        ],
        'no-unused-vars': [
            'error',
            {
                args: 'none'
            }
        ],
        'brace-style': [
            'error',
            'stroustrup',
            {
                allowSingleLine: false
            }
        ],
        'eol-last': [
            'error',
            'always'
        ],
        'space-before-function-paren': [
            'error',
            {
                anonymous: 'never',
                named: 'never',
                asyncArrow: 'always'
            }
        ],
        'keyword-spacing': [
            'error',
            {
                before: true,
                after: true
            }
        ],
        'key-spacing': [
            'error',
            {
                beforeColon: false,
                afterColon: true,
                mode: 'strict'
            }
        ],
        'comma-spacing': [
            'error'
        ],
        'arrow-spacing': [
            'error'
        ],
        'array-bracket-spacing': [
            'error',
            'never',
            {
                singleValue: false,
                objectsInArrays: true,
                arraysInArrays: true
            }
        ],
        'curly': [
            'error'
        ],
        'space-infix-ops': [
            'error',
            {
                int32Hint: false
            }
        ],
        'space-unary-ops': [
            'error',
            {
                words: true,
                nonwords: false
            }
        ],
        'space-before-blocks': [
            'error'
        ],
        'object-curly-spacing': [
            'error',
            'never'
        ],
        'space-in-parens': [
            'error',
            'never'
        ],
        'prefer-arrow-callback': [
            'warn'
        ],
        'no-return-await': [
            'error'
        ],
        'no-console': [
            'warn'
        ],
        'no-nested-ternary': [
            'error'
        ],
        'no-unneeded-ternary': [
            'warn'
        ],
        'no-unexpected-multiline': [
            'error'
        ],
        'lines-around-directive': [
            'error',
            'always'
        ],
        // Disable this because itìs incompatible with svelte
        /*'no-multiple-empty-lines': [
            'error',
            {
                max: 1
            }
        ],*/
        'operator-linebreak': [
            'error',
            'after'
        ]
    }
}
