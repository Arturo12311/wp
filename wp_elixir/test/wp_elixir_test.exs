defmodule WpElixirTest do
  use ExUnit.Case
  doctest WpElixir

  test "greets the world" do
    assert WpElixir.hello() == :world
  end
end
