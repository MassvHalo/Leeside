<?php

namespace Leeside\Laravel\Tests\Unit;

use DateTimeImmutable;
use Leeside\Laravel\Reduce\ShapeReducer;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class ShapeReducerTest extends TestCase
{
    private ShapeReducer $reducer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->reducer = new ShapeReducer;
    }

    public function test_scalars(): void
    {
        $this->assertSame('null', $this->reducer->reduce(null));
        $this->assertSame('bool', $this->reducer->reduce(true));
        $this->assertSame('bool', $this->reducer->reduce(false));
        $this->assertSame('int', $this->reducer->reduce(42));
        $this->assertSame('num', $this->reducer->reduce(4.2));
        $this->assertSame('obj', $this->reducer->reduce(new stdClass));
        $this->assertSame('obj', $this->reducer->reduce(new DateTimeImmutable));
    }

    public function test_resources_are_unknown(): void
    {
        $handle = fopen('php://memory', 'r');

        try {
            $this->assertSame('unk', $this->reducer->reduce($handle));
        } finally {
            fclose($handle);
        }
    }

    public function test_uploaded_files(): void
    {
        $file = new UploadedFile(__FILE__, 'shape.php', 'text/php', UPLOAD_ERR_OK, true);

        $this->assertSame('file', $this->reducer->reduce($file));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('stringLengths')]
    public function test_string_lengths(int $length, string $expected): void
    {
        $this->assertSame($expected, $this->reducer->reduce(str_repeat('a', $length)));
    }

    /** @return array<string, array{int, string}> */
    public static function stringLengths(): array
    {
        return [
            'empty' => [0, 'str:0'],
            'exact' => [6, 'str:6'],
            'at cap' => [64, 'str:64'],
            'over 64' => [65, 'str:>64'],
            'at 256' => [256, 'str:>64'],
            'over 256' => [257, 'str:>256'],
            'at 1k' => [1024, 'str:>256'],
            'over 1k' => [1025, 'str:>1k'],
            'at 4k' => [4096, 'str:>1k'],
            'over 4k' => [4097, 'str:>4k'],
            'at 16k' => [16384, 'str:>4k'],
            'over 16k' => [16385, 'str:>16k'],
            'at 64k' => [65536, 'str:>16k'],
            'over 64k' => [65537, 'str:>64k'],
        ];
    }

    public function test_lists_are_typed_by_the_first_element(): void
    {
        $this->assertSame('[]', $this->reducer->reduce([]));
        $this->assertSame('[int*3]', $this->reducer->reduce([1, 2, 3]));
        $this->assertSame('[str:1*1]', $this->reducer->reduce(['a']));
        $this->assertSame('[int*2]', $this->reducer->reduce([1, 'mixed-types-ignored']));
    }

    public function test_maps_sort_keys(): void
    {
        $this->assertSame('{x:int}', $this->reducer->reduce(['x' => 1]));
        $this->assertSame('{a:int,b:int}', $this->reducer->reduce(['b' => 1, 'a' => 2]));
    }

    public function test_brief_example(): void
    {
        $this->assertSame(
            '{otp:str:6,phone:str:10}',
            $this->reducer->reduce(['otp' => '123456', 'phone' => '0123456789'])
        );
        $this->assertSame(
            '{errors:{otp:[str:23*1]},message:str:23}',
            $this->reducer->reduce(['errors' => ['otp' => [str_repeat('x', 23)]], 'message' => str_repeat('y', 23)])
        );
    }

    public function test_reserved_characters_in_keys_become_underscores(): void
    {
        $this->assertSame(
            '{a_b_c_d_e_f_g_h:int}',
            $this->reducer->reduce(['a:b,c{d}e[f]g*h' => 1])
        );
    }

    public function test_long_keys_are_cut(): void
    {
        $key = str_repeat('k', 40);

        $this->assertSame('{'.str_repeat('k', 24).':int}', $this->reducer->reduce([$key => 1]));
        $this->assertSame('{'.str_repeat('k', 24).':int}', $this->reducer->reduce([str_repeat('k', 24) => 1]));
    }

    public function test_long_numeric_keys_become_hash(): void
    {
        $this->assertSame('{#:int}', $this->reducer->reduce(['123456' => 1]));
        $this->assertSame('{#:int}', $this->reducer->reduce([1234567890 => 1]));
        $this->assertSame('{12345:int}', $this->reducer->reduce([12345 => 1]));
    }

    public function test_depth_cap(): void
    {
        $value = ['a' => ['b' => ['c' => ['d' => ['e' => 1]]]]];

        $this->assertSame('{a:{b:{c:{d:{…}}}}}', $this->reducer->reduce($value));
        $this->assertSame('[[[[[…]*1]*1]*1]*1]', $this->reducer->reduce([[[[[1]]]]]));
    }

    public function test_key_cap(): void
    {
        $value = [];
        for ($i = 0; $i < 35; $i++) {
            $value[sprintf('k%02d', $i)] = $i;
        }

        $shape = $this->reducer->reduce($value);

        $this->assertStringEndsWith(',…+3}', $shape);
        $this->assertStringStartsWith('{k00:int,', $shape);
    }

    public function test_whole_shape_is_cut_at_2kb(): void
    {
        $value = [];
        for ($i = 0; $i < 200; $i++) {
            $value['key_'.$i] = str_repeat('v', 100);
        }

        $shape = $this->reducer->reduce($value);

        $this->assertLessThanOrEqual(2048, strlen($shape));
    }

    public function test_options_override_caps(): void
    {
        $reducer = new ShapeReducer(['max_depth' => 1, 'max_keys' => 1, 'max_shape_length' => 10]);

        $this->assertSame('{a:{…}}', $reducer->reduce(['a' => ['b' => 1]]));
        $this->assertSame('{a:int,…', $reducer->reduce(['a' => 1, 'b' => 2]));
    }
}
