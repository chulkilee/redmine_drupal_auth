require 'drupal_password'

# Separate ActiveRecord for AuthSourceDrupal
class DrupalActiveRecord < ActiveRecord::Base

  # Do sleep between retries after this number of retries
  PAUSE_RETRIES = 5

  # Do sleep for this number of seconds for pausing retrying
  SLEEP_FOR_PAUSE = 1

  # Maximum retries
  MAX_RETRIES = 10
end

# Subclass of AuthSource
class AuthSourceDrupal < AuthSource

  # Drupal role name for allowing authentication
  ROLE_NAME = 'redmine user'

  # Auth source name
  AUTH_NAME = 'Drupal'

  # authentication() implementation
  #
  # @param login what user entered for their login
  # @param password what user entered for their password
  def authenticate(login, password)
    result = nil

    unless(login.blank? or password.blank?)
      # get the DB Adapter name and database to use for connecting db
      adapter, db_name = self.base_dn.split(':')

      # get a connection
      retry_num = 0
      begin
        conn_pool = DrupalActiveRecord.establish_connection(
          :adapter  => adapter,
          :host     => self.host,
          :port     => self.port,
          :username => self.account,
          :password => self.account_password,
          :database => db_name,
          :reconnect => true
        )
        db = conn_pool.checkout()
      rescue => err # retry given times if something goes wrong
        if retry_num < DrupalActiveRecord::MAX_RETRIES
          sleep SLEEP_FOR_PAUSE if retry_num < DrupalActiveRecord::PAUSE_RETRIES
          retry_num += 1
          conn_pool.disconnect!
          retry
        else # throw error to Redmine
          throw err
        end
      end

      # query the alternative authentication database for needed info
      query = [
        'SELECT name, pass, mail ' +
        'FROM users u, users_roles ur, (SELECT rid FROM role WHERE name=?) r ' +
        'WHERE u.uid=ur.uid AND ur.rid = r.rid AND status = 1 AND name=?',
        ROLE_NAME, login]
      sql =  ActiveRecord::Base.__send__(:sanitize_sql, query, '')
      result_row = db.select_one(sql)

      unless(result_row.nil? or result_row.empty?)
        stored_hash = result_row['pass']
        if DrupalPassword.matches? password, stored_hash # found a match
          # If allowing Redmine to automatically register such accounts in its
          # internal table, return account information to Redmine based on
          # record found.
          if onthefly_register?
            result = {
              :firstname => result_row['name'],
              :lastname => result_row['name'],
              :mail => result_row['mail'],
              :auth_source_id => self.id,
            }
          end
        end
      end
    end
    # check connection back into pool.
    conn_pool.checkin(db)
    return result
  end

  # Return AUTH_NAME
  # @return auth name
  def auth_method_name
    AUTH_NAME
  end
end
