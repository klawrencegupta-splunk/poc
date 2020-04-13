module ExitCodes
    NO_SPLUNK_HOME = 1
    NO_NODE = 2
    NO_SPLUNK_WEB_CORE = 3
end

# Recall that pwd is set to the root of the project, no matter where
# the rake command is invoked within the file tree.
APP_SOURCE = Dir.pwd
SPLUNK_WEB_CORE_LOCAL = Dir.pwd + '/SplunkWebCore'
SPLUNK_WEB_CORE_HOME = Dir.exists?(SPLUNK_WEB_CORE_LOCAL) ? SPLUNK_WEB_CORE_LOCAL : "#{ENV['SPLUNK_SOURCE']}/web"

APP_NAME = File.basename(File.dirname(__FILE__))
APP_HOME = "#{ENV['SPLUNK_HOME']}/etc/apps/#{APP_NAME}"

unless Dir.exists?(SPLUNK_WEB_CORE_HOME)
    $stderr.puts "Could not find SplunkWebCore. Please install it at ./SplunkWebCore or set $SPLUNK_SOURCE"
    exit ExitCodes::NO_SPLUNK_WEB_CORE
end

desc 'Build the app'
task :build => :assert_node_installed do
    sh "node #{SPLUNK_WEB_CORE_HOME}/build.js -pa #{Dir.pwd}"
end

desc 'Run the file watcher'
task :watch do
    sh "node #{SPLUNK_WEB_CORE_HOME}/build_tools/build.js -dwr #{SPLUNK_WEB_CORE_HOME}/build_tools/profiles/common/appPages.config.js #{Dir.pwd} #{File.basename(Dir.pwd)}"
end

desc 'Clean the app'
task :clean do
    sh 'rm -rf appserver/static/build/'
end

desc 'Install the app by copying into $SPLUNK_HOME/etc/apps'
task :install => [:assert_splunk_home_found, :uninstall] do
    sh "cp -R #{APP_SOURCE} #{APP_HOME}"
end

desc 'Install the app by symlink'
task :symlink => [:assert_splunk_home_found, :uninstall] do
    sh "ln -s #{APP_SOURCE} #{APP_HOME}"
end

desc 'Uninstall the app'
task :uninstall do
    rm_rf APP_HOME
end

# Helper Tasks
# ------------

# Having no `desc` description hides these from `rake -T` & `rake -D` output,
# unless `-A` or `--all` are also used.

task :assert_splunk_home_found do
    unless ENV['SPLUNK_HOME'] && Dir.exists?(ENV['SPLUNK_HOME'])
        $stderr.puts "ERROR: SPLUNK_HOME not set, or does not point to a directory."
        exit ExitCodes::NO_SPLUNK_HOME
    end
end

task :assert_node_installed do
    if `which node`.strip.empty?
        $stderr.puts "ERROR: Nodejs required. Please install it and try again."
        $stderr.puts "See: https://xkcd.com/1654/ if you need help installing node."
        exit ExitCodes::NO_NODE
    end
end
