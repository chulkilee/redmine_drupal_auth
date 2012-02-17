require 'digest'
require 'base64'

# Based on Drupal 7 Core includes/password.inc
module DrupalPassword

  # The minimum allowed log2 number of iterations for password stretching.
  DRUPAL_MIN_HASH_COUNT = 7

  # The maximum allowed log2 number of iterations for password stretching.
  DRUPAL_MAX_HASH_COUNT = 30

  # The expected (and maximum) number of characters in a hashed password.
  DRUPAL_HASH_LENGTH = 55

  # A string for mapping an int to the corresponding base 64 character.
  ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

  # Hash a password using a secure stretched hash.
  #
  # By using a salt and repeated hashing the password is "stretched". Its
  # security is increased because it becomes much more computationally costly
  # for an attacker to try to break the hash by brute-force computation of the
  # hashes of a large number of plain-text words or strings to find a match.
  #
  # @param algo The string name of a hashing algorithm usable by hash(), like 'sha256'.
  # @param password The plain-text password to hash.
  # @param setting An existing hash or the output of _password_generate_salt().  Must be
  #   at least 12 characters (the settings and salt).
  # @return A string containing the hashed password (and salt) or FALSE on failure.
  #   The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
  def self._password_crypt(algo, password, setting)
    # The first 12 characters of an existing hash are its setting string.
    setting = setting[0, 12]
    return false if setting[0, 1] != '$' || setting[2, 1] != '$'
    count_log2 = _password_get_count_log2(setting)
    # Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
    return false if count_log2 < DRUPAL_MIN_HASH_COUNT or count_log2 > DRUPAL_MAX_HASH_COUNT

    salt = setting[4, 8]
    # Hashes must have an 8 character salt.
    return false unless salt.length == 8
    # Convert the base 2 logarithm into an integer.
    count = 1 << count_log2

    hash = _hash algo, salt + password, true

    # do-while
    while true
      hash = _hash algo, hash + password, true
      count -= 1
      break if count == 0
    end

    len = hash.length
    output = setting + _password_base64_encode(hash, len)
    # _password_base64_encode() of a 16 byte MD5 will always be 22 characters.
    # _password_base64_encode() of a 64 byte sha512 will always be 86 characters.
    expected = 12 + ((8.0 * len) / 6).ceil
    if output.length == expected
      return output[0, DRUPAL_HASH_LENGTH]
    else
      return false
    end
  end

  # Parse the log2 iteration count from a stored hash or setting string.
  #
  # @return an integer
  def self._password_get_count_log2(setting)
    return ITOA64.index setting[3]
  end

  # Returns the ASCII value of the first character of string. (like PHP)
  #
  # @return the ASCII value as an integer
  def self.ord(d)
    d[0].ord
  end

  # Encode bytes into printable base 64 using the *nix standard from crypt().
  #
  # @param input The string containing bytes to encode.
  # @param count The number of characters (bytes) to encode.
  # @return encoded string
  def self._password_base64_encode(input, count)
    output = ''
    i = 0
    while true
      value = ord(input[i, 1])
      i += 1
      output += ITOA64[value & 0x3f, 1]

      if i < count
        value |= ord(input[i, 1]) << 8
      end
      output += ITOA64[(value >> 6) & 0x3f, 1]

      if i >= count
        break;
      end
      i += 1

      if i < count
        value |= ord(input[i, 1]) << 16
      end
      output += ITOA64[(value >> 12) & 0x3f, 1]

      if i >= count
        break
      end
      i += 1
      output += ITOA64[(value >> 18) & 0x3f, 1]
      break unless i < count
    end

    return output
  end

  # Check whether a plain text password matches a stored hashed password.
  #
  # @param password A plain-text password
  # @param pw_field a string stored in password field
  # @return true or false
  def self.matches?(password, pw_field)
    if pw_field.start_with? 'U$'
      # This may be an updated password from user_update_7000(). Such hashes
      # have 'U' added as the first character and need an extra md5().
      stored_hash = pw_field[1..-1]
      password = Digest::MD5.digest(password)
    else
      stored_hash = pw_field
    end

    type = stored_hash[0, 3]
    if type == '$S$'
      hash = _password_crypt 'sha512', password, stored_hash
    elsif ['$H$', '$P$'].include? type
      # phpBB3 uses "$H$" for the same thing as "$P$".
      # A phpass password generated using md5.  This is an
      # imported password or from an earlier Drupal version.
      hash = _password_crypt 'md5', password, stored_hash
    else
      return false
    end

    return hash && stored_hash == hash
  end

  # Do like hash() in PHP
  # @param algo sha512 or md5
  # @param data
  # @param raw_output
  def self._hash(algo, data, raw_output = true)
    if algo == 'sha512'
      if raw_output
        return Digest::SHA512.digest data
      else
        return Digest::SHA512.hexdigest data
      end
    elsif algo == 'md5'
      return Digest::MD5.digest(data)
    else
      return false
    end
  end
end
