<?php declare(strict_types=1);

return new PhpCsFixer\Config()
    ->setParallelConfig(PhpCsFixer\Runner\Parallel\ParallelConfigFactory::detect())
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => false,
        'protected_to_private' => false,
        'declare_strict_types' => true,
        'linebreak_after_opening_tag' => false,
        'blank_line_after_opening_tag' => false,
        'phpdoc_annotation_without_dot' => false,
        'yoda_style' => false,
        'single_line_throw' => false,
        'native_function_invocation' => [
            'include' => ['@internal'],
        ],
    ])
    ->setRiskyAllowed(true)
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->in([__DIR__.'/src', __DIR__.'/tests'])
            ->append([__FILE__])
    )
;
