<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class ProductResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array|\Illuminate\Contracts\Support\Arrayable|\JsonSerializable
     */
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'product_name' => $this->name,
            'product_price' => "$" . $this->price,
            'discounted_price' => "$" . ($this->price * 0.9),
            'discount' => "$" . ($this->price * 0.1),
            'product_description' => $this->description,
        ];
    }
}
