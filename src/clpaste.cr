require "./clpaste/config"
require "./clpaste/crypto"
require "./clpaste/ids"
require "./clpaste/model"
require "./clpaste/net"
require "./clpaste/repo"
require "./clpaste/database"
require "./clpaste/access"
require "./clpaste/service"
require "./clpaste/oidc"
require "./clpaste/views"
require "./clpaste/server"
require "./clpaste/cli"

module Clpaste
  def self.main
    Config.init
    if ARGV.empty? || ARGV.first.in?("--help", "-h", "help")
      puts CLI.full_help
      return
    end
    begin
      Config.setup! # consumes recognised --flags from ARGV; subcommand flags remain
    rescue e : Superconf::Error
      STDERR.puts "configuration error: #{e.message}"
      exit 2
    end
    CLI.new(ARGV).run
  rescue e : IO::Error
    # `clpaste get ID | head` etc.: a closed pipe is not an error worth a trace.
    exit 0 if e.message.to_s.includes?("Broken pipe")
    raise e
  end
end

Clpaste.main
