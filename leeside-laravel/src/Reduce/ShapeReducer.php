<?php

namespace Leeside\Laravel\Reduce;

use Symfony\Component\HttpFoundation\File\UploadedFile;

class ShapeReducer
{
    private readonly int $maxDepth;
    private readonly int $maxKeys;
    private readonly int $maxShapeLength;

    /**
     * @param  array{max_depth?: int, max_keys?: int, max_shape_length?: int}  $options
     */
    public function __construct(array $options = [])
    {
        $this->maxDepth = $options['max_depth'] ?? 4;
        $this->maxKeys = $options['max_keys'] ?? 32;
        $this->maxShapeLength = $options['max_shape_length'] ?? 2048;
    }

    /** Keys and types, never values. */
    public function reduce(mixed $value): string
    {
        return $this->cut($this->shape($value, 0));
    }

    private function shape(mixed $value, int $depth): string
    {
        if (is_array($value)) {
            return $this->arrayShape($value, $depth);
        }

        if (is_string($value)) {
            return $this->stringShape(strlen($value));
        }

        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return 'bool';
        }

        if (is_int($value)) {
            return 'int';
        }

        if (is_float($value)) {
            return 'num';
        }

        if ($value instanceof UploadedFile) {
            return 'file';
        }

        if (is_object($value)) {
            return 'obj';
        }

        return 'unk';
    }

    private function arrayShape(array $value, int $depth): string
    {
        if (array_is_list($value)) {
            return $this->listShape($value, $depth);
        }

        return $this->mapShape($value, $depth);
    }

    private function listShape(array $value, int $depth): string
    {
        if ($value === []) {
            return '[]';
        }

        if ($depth >= $this->maxDepth) {
            return '[…]';
        }

        return '['.$this->shape($value[0], $depth + 1).'*'.count($value).']';
    }

    private function mapShape(array $value, int $depth): string
    {
        if ($value === []) {
            return '{}';
        }

        if ($depth >= $this->maxDepth) {
            return '{…}';
        }

        $entries = [];
        foreach ($value as $key => $item) {
            $entries[$this->sanitizeKey($key)][] = $this->shape($item, $depth + 1);
        }
        ksort($entries, SORT_STRING);

        $flat = [];
        foreach ($entries as $key => $shapes) {
            foreach ($shapes as $shape) {
                $flat[] = $key.':'.$shape;
            }
        }

        $extra = count($flat) - $this->maxKeys;
        if ($extra > 0) {
            $flat = array_slice($flat, 0, $this->maxKeys);
            $flat[] = '…+'.$extra;
        }

        return '{'.implode(',', $flat).'}';
    }

    private function stringShape(int $length): string
    {
        return match (true) {
            $length <= 64 => 'str:'.$length,
            $length <= 256 => 'str:>64',
            $length <= 1024 => 'str:>256',
            $length <= 4096 => 'str:>1k',
            $length <= 16384 => 'str:>4k',
            $length <= 65536 => 'str:>16k',
            default => 'str:>64k',
        };
    }

    private function sanitizeKey(int|string $key): string
    {
        $key = (string) $key;

        if (preg_match('/^\d{6,}$/', $key) === 1) {
            return '#';
        }

        $key = str_replace([':', ',', '{', '}', '[', ']', '*'], '_', $key);

        if (function_exists('mb_substr')) {
            return mb_substr($key, 0, 24, 'UTF-8');
        }

        return substr($key, 0, 24);
    }

    private function cut(string $shape): string
    {
        if (strlen($shape) <= $this->maxShapeLength) {
            return $shape;
        }

        if (function_exists('mb_strcut')) {
            return mb_strcut($shape, 0, $this->maxShapeLength, 'UTF-8');
        }

        return substr($shape, 0, $this->maxShapeLength);
    }
}
