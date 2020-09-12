<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SignupRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ];
    }

     /**
     *
     * @OA\Schema(
     *     schema="SignupRequest",
     *     title="SignupRequest",
     *     description="Signup Request",
     *     @OA\Property(type="string", property="name", description="Nombre del usuario"),
     *     @OA\Property(type="string", property="email", format="email", description="Email del usuario"),
     *     @OA\Property(type="string", property="password", format="password", description="Contraseña del usuario")
     * )
     */
}
