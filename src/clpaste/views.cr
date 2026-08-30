require "crinja"

module Clpaste
  # Template rendering. Built-in templates and static assets are compiled
  # into the binary; `theme_dir` may override any of them at runtime.
  class Views
    TEMPLATE_NAMES = %w[layout.html index.html created.html gate.html paste.html
      message.html list.html detail.html login.html cli_code.html]

    BUILTIN_TEMPLATES = {
      "layout.html"   => {{ read_file("#{__DIR__}/../../templates/layout.html") }},
      "index.html"    => {{ read_file("#{__DIR__}/../../templates/index.html") }},
      "created.html"  => {{ read_file("#{__DIR__}/../../templates/created.html") }},
      "gate.html"     => {{ read_file("#{__DIR__}/../../templates/gate.html") }},
      "paste.html"    => {{ read_file("#{__DIR__}/../../templates/paste.html") }},
      "message.html"  => {{ read_file("#{__DIR__}/../../templates/message.html") }},
      "list.html"     => {{ read_file("#{__DIR__}/../../templates/list.html") }},
      "detail.html"   => {{ read_file("#{__DIR__}/../../templates/detail.html") }},
      "login.html"    => {{ read_file("#{__DIR__}/../../templates/login.html") }},
      "cli_code.html" => {{ read_file("#{__DIR__}/../../templates/cli_code.html") }},
    }

    BUILTIN_STATIC = {
      "bootstrap.min.css" => {{ read_file("#{__DIR__}/../../assets/bootstrap.min.css") }},
      "app.css"           => {{ read_file("#{__DIR__}/../../assets/app.css") }},
    }

    getter env : Crinja
    @theme_dir : String?

    def initialize(theme_dir : String)
      @theme_dir = theme_dir.presence
      loaders = [] of Crinja::Loader
      if d = @theme_dir
        raise "theme_dir #{d} does not exist" unless Dir.exists?(d)
        loaders << Crinja::Loader::FileSystemLoader.new(d)
      end
      loaders << Crinja::Loader::HashLoader.new(BUILTIN_TEMPLATES)
      @env = Crinja.new
      @env.loader = Crinja::Loader::ChoiceLoader.new(loaders)
      @env.config.autoescape = true
    end

    def render(name : String, vars) : String
      @env.get_template(name).render(vars)
    end

    # Returns {content, content_type} or nil.
    def static(name : String) : {String, String}?
      return if name.includes?("..") || name.includes?('/')
      if d = @theme_dir
        p = File.join(d, "static", name)
        return {File.read(p), mime(name)} if File.file?(p)
      end
      BUILTIN_STATIC[name]?.try { |content| {content, mime(name)} }
    end

    private def mime(name : String) : String
      case File.extname(name)
      when ".css" then "text/css; charset=utf-8"
      when ".js"  then "application/javascript"
      when ".png" then "image/png"
      when ".svg" then "image/svg+xml"
      when ".ico" then "image/x-icon"
      else             "application/octet-stream"
      end
    end
  end
end
