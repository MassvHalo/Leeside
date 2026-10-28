<?php

namespace Database\Seeders;

use App\Models\Venue;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $venues = [
            ['Alpine Lodge', 'Innsbruck'],
            ['Harbor Inn', 'Bergen'],
            ['Desert Rose', 'Marrakech'],
            ['City Central', 'Oslo'],
            ['Lakeside Retreat', 'Geneva'],
            ['Old Town Hostel', 'Lisbon'],
        ];

        foreach ($venues as [$name, $city]) {
            Venue::create(['name' => $name, 'city' => $city]);
        }
    }
}
