require 'sinatra/base'
require 'mysql2'
require 'rack-flash'
require 'digest/md5'
require 'pp'

module Isuconp
  class App < Sinatra::Base
    use Rack::Session::Cookie, secret: ENV['ISUCONP_SESSION_SECRET'] || 'sendagaya'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)
    set :absolute_redirects, true

    helpers do
      def config
        @config ||= {
          db: {
            host: ENV['ISUCONP_DB_HOST'] || 'localhost',
            port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCON5_DB_PORT'].to_i,
            username: ENV['ISUCONP_DB_USER'] || 'root',
            password: ENV['ISUCONP_DB_PASSWORD'],
            database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
          },
        }
      end

      def db
        return Thread.current[:isuconp_db] if Thread.current[:isuconp_db]
        client = Mysql2::Client.new(
          host: config[:db][:host],
          port: config[:db][:port],
          username: config[:db][:username],
          password: config[:db][:password],
          database: config[:db][:database],
          encoding: 'utf8mb4',
          reconnect: true,
        )
        client.query_options.merge!(symbolize_keys: true)
        Thread.current[:isuconp_db] = client
        client
      end

      def try_login(account_name, password)
        user = db.prepare('SELECT * FROM users WHERE account_name = ? AND del_flg = 0').execute(account_name).first

        if user && calculate_passhash(password, user[:account_name]) == user[:passhash]
          return user
        elsif user
          return nil
        else
          return nil
        end
      end

      def register_user(account_name:, password:)
        validated = validate_user(
          account_name: account_name,
          password: password
        )
        if !validated
          return false
        end

        user = db.prepare('SELECT 1 FROM users WHERE `account_name` = ?').execute(account_name).first
        if user
          return false
        end

        query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)'
        db.prepare(query).execute(
          account_name,
          calculate_passhash(password, account_name)
        )

        return true
      end

      def validate_user(account_name:, password:)
        unless /\A[0-9a-zA-Z_]{3,}\z/.match(account_name)
          return false
        end

        if password.length <= 7
          return false
        end

        return true
      end

      def calculate_passhash(password, account_name)
        salt = calculate_salt(account_name)
        Digest::SHA256.hexdigest("#{password}:#{salt}")
      end

      def calculate_salt(account_name)
        Digest::MD5.hexdigest(account_name)
      end
    end

    get '/login' do
      if session[:user]
        redirect '/', 302
      end
      erb :login, layout: :layout
    end

    post '/login' do
      if session[:user] && session[:user][:id]
        # ログイン済みはリダイレクト
        redirect '/', 302
      end

      user = try_login(params['account_name'], params['password'])
      if user
        session[:user] = {
          id: user[:id]
        }
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名かパスワードが間違っています'
        redirect '/login', 302
      end
    end

    get '/register' do
      if session[:user]
        redirect '/', 302
      end
      erb :register, layout: :layout
    end

    post '/register' do
      if session[:user] && session[:user][:id]
        # ログイン済みはリダイレクト
        redirect '/', 302
      end

      result = register_user(
        account_name: params['account_name'],
        password: params['password']
      )
      if result
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名がすでに使われています'
        redirect '/register', 302
      end
    end

    get '/logout' do
      session.delete(:user)
      redirect '/', 302
    end

    get '/' do
      posts = db.query('SELECT * FROM posts ORDER BY id DESC LIMIT 30')
      cs = db.prepare('SELECT * FROM comments WHERE post_id IN (%s)' % [posts.map { '?' }.join(',')]).execute(*posts.map {|i| i[:id]})
      comments = {}
      cs.each do |c|
        if !comments[c[:post_id]]
          comments[c[:post_id]] = [c]
        else
          comments[c[:post_id]].push(c)
        end
      end

      user = {}
      if session[:user]
        user = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
          session[:user][:id]
        ).first
      else
        user = { id: 0 }
      end

      user_ids = [posts.map {|i| i[:user_id] }, comments.map {|k,v| v.map {|i| i[:user_id] }}].flatten.uniq
      users_raw = db.prepare('SELECT * FROM `users` WHERE id IN (%s)' % [user_ids.map { '?' }.join(',')]).execute(*user_ids)
      users = {}
      users_raw.each do |u|
        users[u[:id]] = u
      end

      erb :index, layout: :layout, locals: { posts: posts, comments: comments, users: users, user: user }
    end

    post '/' do
      unless session[:user] && session[:user][:id]
        # 非ログインはリダイレクト
        redirect '/login', 302
      end

      if params['csrf_token'] != session.id
        return 'csrf_token error'
      end

      if params['file']
        mime = ''
        ext = ''
        # 投稿のContent-Typeからファイルのタイプを決定する
        if params["file"][:type].include? "jpeg"
          mime = "image/jpeg"
          ext = 'jpg'
        elsif params["file"][:type].include? "png"
          mime = "image/png"
          ext = 'png'
        elsif params["file"][:type].include? "gif"
          mime = "image/gif"
          ext = 'gif'
        else
          flash[:notice] = '投稿できる画像形式はjpgとpngとgifだけです'
          redirect '/', 302
        end

        query = 'INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)'
        binary = params["file"][:tempfile].read
        result = db.prepare(query).execute(
          session[:user][:id],
          mime,
          params["body"],
        )
        result = db.prepare('SELECT LAST_INSERT_ID() AS id').execute().first
        File.open("#{settings.public_folder}/image/#{result[:id]}", 'wb') do |f|
          f.print(binary)
        end

        redirect '/', 302
      else
        flash[:notice] = '画像が必須です'
        redirect '/', 302
      end
    end

    # get '/image/:id' do
    #   if params[:id].to_i == 0
    #     return ""
    #   end

    #   post = db.prepare('SELECT * FROM posts WHERE id = ?').execute(params[:id].to_i).first
    #   ext = case post[:mime]
    #   when 'image/jpeg'
    #     'jpg'
    #   when 'image/png'
    #     'png'
    #   when 'image/gif'
    #     'gif'
    #   end
    #   redirect "/image/#{params[:id].to_i}.#{ext}"
    # end

    post '/comment' do
      unless session[:user] && session[:user][:id]
        # 非ログインはリダイレクト
        redirect '/login', 302
      end

      if params["csrf_token"] != session.id
        return "csrf_token error"
      end

      query = 'INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)'
      db.prepare(query).execute(
        params['post_id'],
        session[:user][:id],
        params['comment']
      )

      redirect '/', 302
    end

    get '/notify' do
      comments = db.query('SELECT * FROM `comments` ORDER BY `created_at` DESC')
      notifies = []

      comments.each do |c|
        if c[:user_id] == session[:user][:id]
          notifies.push(c)
        end
      end

      erb :notify, layout: :layout, locals: { notifies: notifies }
    end

    get '/admin/banned' do
      if !session[:user]
        redirect '/login', 302
      end

      user = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
        session[:user][:id]
      ).first

      if user[:authority] == 0
        return 403
      end

      users = db.query('SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC')

      erb :banned, layout: :layout, locals: { users: users }
    end

    post '/admin/banned' do
      unless session[:user] && session[:user][:id]
        # 非ログインはリダイレクト
        redirect '/', 302
      end

      user = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
        session[:user][:id]
      ).first

      if user[:authority] == 0
        return 403
      end

      if params['csrf_token'] != session.id
        return 403
      end

      query = 'UPDATE `users` SET `del_flg` = ? WHERE `id` = ?'

      params['uid'].each do |id|
        db.prepare(query).execute(1, id.to_i)
      end

      redirect '/admin/banned', 302
    end

    get '/mypage' do
      unless session[:user] && session[:user][:id]
        # 非ログインはリダイレクト
        redirect '/', 302
      end

      posts_all = db.prepare('SELECT * FROM `posts` WHERE user_id = ? ORDER BY `id` DESC').execute(session[:user][:id])
      posts = posts_all
      if posts_all.size > 0
        comments_all = db.prepare('SELECT * FROM `comments` WHERE post_id IN (%s) ORDER BY `id` DESC' % [posts_all.map { '?' }.join(',')]).execute(*posts_all.map {|i| i[:id]})
      else
        comments_all = []
      end
      posts = []
      comments = []

      comments_all.each do |c|
        if c[:user_id] == session[:user][:id]
          comments.push(c)
        end
      end

      mixed = []
      index = 0

      (0..(posts.length - 1)).each do |pi|
        if comments.length > 0 && comments[index][:created_at] > posts[pi][:created_at]
          mixed.push({type: :comment, value: comments[index]})
        else
          mixed.push({type: :post, value: posts[pi]})
        end

        if index < comments.length - 1
          index += 1
        else
          (pi..(posts.length - 1)).each do |i|
            mixed.push({type: :post, value: posts[i]})
          end
        end
      end

      user = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
        session[:user][:id]
      ).first

      erb :mypage, layout: :layout, locals: { mixed: mixed, user: user }
    end

  end
end
