<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 *  @OA\Info(
 *      description="API AuthController",
 *      version="1.0.0",
 *      title="wday",
 *  )
 */

/**
 *  @OA\SecurityScheme(
 *      securityScheme="bearerAuth",
 *      type="http",
 *      scheme="bearer",
 *  )
 */
class AuthController extends Controller
{
    /**
     * @OA\Post(
     *      path="/api/auth/signup",
     *      tags={"AuthController"},
     *      summary="Registro de usuario",
     *      operationId="register",
     *      @OA\Parameter(
     *          name="Register",
     *          in="query",
     *          @OA\JsonContent(ref="#/components/schemas/SignupRequest"),
     *      ),
     *  @OA\Response(
     *      response=201,
     *      description="Usuario creado",
     *      @OA\MediaType(
     *          mediaType="application/json",
     *      )
     *  ),
     *  @OA\Response(
     *      response=400,
     *      description="Solicitud no válida"
     *  ),
     *  @OA\Response(
     *      response=404,
     *      description="No encontrado"
     *  ),
     *  @OA\Response(
     *      response=422,
     *      description="Error validación"
     *  )
     *)
     */
    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
        $user->save();

        $user->notify(new SignupActivate($user));

        return response()->json(['message' => 'Usuario creado correctamente'], 201);
    }

    /**
     * @OA\Post(
     *      path="/api/auth/login",
     *      tags={"AuthController"},
     *      summary="Login de usuario",
     *      operationId="login",
     *      @OA\Parameter(
     *          name="Login",
     *          in="query",
     *          @OA\JsonContent(ref="#/components/schemas/LoginRequest"),
     *      ),
     *  @OA\Response(
     *      response=201,
     *      description="Usuario creado",
     *      @OA\MediaType(
     *          mediaType="application/json",
     *      )
     *  ),
     *  @OA\Response(
     *      response=400,
     *      description="Solicitud no válida"
     *  ),
     *  @OA\Response(
     *      response=401,
     *      description="No autorizado"
     *  ),
     *  @OA\Response(
     *      response=404,
     *      description="No encontrado"
     *  ),
     *  @OA\Response(
     *      response=422,
     *      description="Error validación"
     *  )
     *)
     */
    public function login(LoginRequest $request)
    {
        $credential = request(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;
        if (!Auth::attempt($credential)) {
            return response()->json(['message' => 'Desautorizado'], 401);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('Pesonal Access Token');
        $token = $tokenResult->token;

        if ($request->remember_me) {
            $token->expired_at = Carbon::now()->addWeek(1);
        }
        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type'   => 'Bearer',
            'expires_at'   => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString(),
        ]);
    }

    /**
     * @OA\Get(
     *      path="/api/auth/logout",
     *      tags={"AuthController"},
     *      summary="Logout de usuario",
     *      operationId="logout",
     *      security={{"bearerAuth":{}}},
     *
     *      @OA\Response(
     *          response=201,
     *          description="Usuario creado",
     *          @OA\MediaType(
     *              mediaType="application/json",
     *          )
     *      ),
     *      @OA\Response(
     *          response=400,
     *          description="Solicitud no válida"
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="No autorizado"
     *      ),
     *      @OA\Response(
     *          response=404,
     *          description="No encontrado"
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Error validación"
     *      )
     *  )
     */
    public function logOut(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(['message' => 'Cerrar sesión exitosa']);
    }

    /**
     * @OA\Get(
     *      path="/api/auth/user",
     *      tags={"AuthController"},
     *      summary="Datos del usuario",
     *      operationId="user",
     *      security={{"bearerAuth":{}}},
     *
     *      @OA\Response(
     *          response=200,
     *          description="Usuario",
     *          @OA\JsonContent(ref="#/components/schemas/User"),
     *      ),
     *      @OA\Response(
     *          response=400,
     *          description="Solicitud no válida"
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="No autorizado"
     *      ),
     *      @OA\Response(
     *          response=404,
     *          description="No encontrado"
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Error validación"
     *      )
     *  )
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    public function signupActivate($token)
    {
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json(['message' => 'El token de activación es inválido'], 404);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->save();
        return $user;
    }
}
