<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use App\Models\User;
use GuzzleHttp\Client;
use Laravel\Passport\Client as OClient;
class PassportAuthController extends Controller
{
    //
    /**
     * Registration
     */
    public function register(Request $request){

        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'c_password' => 'required|same:password',
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }
         $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('MyApp')->accessToken;
        $success['name'] =  $user->name;
   
        return $this->sendResponse($success, 'User register successfully.');
        // $user= User::create([
        //     'name' => $request->name,
        //     'email' => $request->email,
        //     'password' => bcrypt($request->password)
        // ]);
        // var_dump($user);
        // $oClient = OClient::where('password_client',1)->first();
        // return $this->getTokenAndRefreshToken($oClient, $user->email, $user->password);
        // $token = $user->createToken('LaravelAuthApp')->accessToken;
        // return response()->json(['token'=>$token],200);
    }
    /**
     * Login
     */
    public function login(Request $request){
        // $data=['email'=>$request->email, 'password'=>$request->password];
        // var_dump($data);
    //     var_dump(auth()->attempt(['email' => request('email'), 'password' => request('password')]));
    //     if (Auth::attempt(['email' => request('email'), 'password' => request('password')])) {
    //      $oClient = OClient::where("password_client",1)->first();
    //      return $this->getTokenAndRefreshToken($oClient, request('email'),request('password'));
    // //   return response()->json($this->getTokenAndRefreshToken($oClient, request('email'), request('password')),200);

    //     }else {
    //         return response()->json(['error' =>'Unauthorized'],401);
    //     }
    if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){ 
            $user = Auth::user(); 
            $success['token'] =  $user->createToken('MyApp')->accessToken; 
            $success['name'] =  $user->name;
            return $this->sendResponse($success, 'User login successfully.');
        } 
        else{ 
            return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
        } 
    }

public function getTokenAndRefreshToken(OClient $oClient, $email, $password) {
      $oClient = OClient::where('password_client',1)->first();
      $http = new Client;
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
