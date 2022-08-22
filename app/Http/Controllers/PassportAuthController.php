<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Laravel\Passport\Client as OClient;
use GuzzleHttp\Client;
class PassportAuthController extends Controller
{
    //
    /**
     * Registration
     */
    public function register(Request $request){

        $this->validate($request,[
            'name'=>'required|min:4',
            'email'=>'required|email',
            'password'=>'required|min:8'
        ]);
        $user= User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
        var_dump($user);
        $oClient = OClient::where('password_client',1)->first();
        return $this->getTokenAndRefreshToken($oClient, $user->email, $user->password);
        // $token = $user->createToken('LaravelAuthApp')->accessToken;
        // return response()->json(['token'=>$token],200);
    }
    /**
     * Login
     */
    public function login(Request $request){
        $data=['email'=>$request->email, 'password'=>$request->password];
        // var_dump($data);
        // var_dump(auth()->attempt($data));
        if(auth()->attempt($data)){
         $oClient = OClient::where("password_client",1)->first();
         return $this->getTokenAndRefreshToken($oClient, request('email'),request('password'));
      return response()->json($this->getTokenAndRefreshToken($oClient, request('email'), request('password')),200);

        }else {
            return response()->json(['error' =>'Unauthorized'],401);
        }
    }

public function getTokenAndRefreshToken(OClient $oClient, $email, $password) {
      $oClient = OClient::where('password_client',1)->first();
      $http = new OClient;
      $response = $http->request('POST', 'http://localhost:8000/oauth/token', [
          'form_params' => [
              'grant_type' => 'password',
              'client_id' => $oClient->id,
              'client_secret' => $oClient->secret,
              'username' => $email,
              'password' => $password,
              'scope' => '*',
          ],
      ]);

      $result = json_decode((string) $response->getBody(), true);
      return response()->json($result,200);
  }
}
