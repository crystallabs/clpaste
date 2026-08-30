module Clpaste::Ids
  # Random decimal ID with a fixed number of digits (first digit non-zero).
  def self.generate(digits : Int32 = Superconf.id_digits) : String
    String.build(digits) do |io|
      io << Random::Secure.rand(1..9)
      (digits - 1).times { io << Random::Secure.rand(0..9) }
    end
  end

  # Strips dashes, spaces and anything non-digit. Returns nil if the result
  # is not a plausible ID (6..18 digits).
  def self.normalize(input : String) : String?
    d = input.gsub(/[^0-9]/, "")
    return if d.size < 6 || d.size > 18
    d
  end

  # 1234567890 => 123-456-789-0
  def self.format(id : String) : String
    id.scan(/.{1,3}/).map(&.[0]).join('-')
  end
end
