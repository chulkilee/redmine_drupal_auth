require 'test_helper'

class DrupalPasswordTest < ActiveSupport::TestCase
  test 'Test matches? method' do
    pw_field = '$S$Cj2LSFHNpJKa8DtM47ANlUaRfBqdrSY7346FHCbooPWI9I6YPKNk'
    password = 'test'

    assert DrupalPassword.matches?(password, pw_field)
    assert !DrupalPassword.matches?(password + 'wrong', pw_field)
  end
end
