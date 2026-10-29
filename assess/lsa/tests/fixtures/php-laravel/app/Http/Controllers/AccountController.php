<?php
namespace App\Http\Controllers;

use App\Models\Post;
use App\Models\Team;
use App\Models\User;
use Illuminate\Http\Request;

class AccountController extends Controller
{
    public function register(Request $request)
    {
        return User::create($request->all()); // LSA-EXPECT:MASS
    }

    public function post(Request $request)
    {
        return Post::create($request->all()); // LSA-EXPECT:SAFE-MASS
    }

    public function team(Request $request)
    {
        return Team::create($request->all()); // LSA-EXPECT:MASS
    }

    public function rename(Request $request)
    {
        $user = $request->user();
        $user->update($request->only(['name'])); // LSA-EXPECT:SAFE-MASS
        return $user;
    }

    public function profile(Request $request)
    {
        $user = $request->user();
        $user->fill($request->all())->save(); // LSA-EXPECT:MASS
        return $user;
    }
}
