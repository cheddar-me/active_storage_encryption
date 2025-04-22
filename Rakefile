# frozen_string_literal: true

require "bundler/setup"
require "bundler/gem_tasks"
require "rake/testtask"


APP_RAKEFILE = File.expand_path("test/dummy/Rakefile", __dir__)
load "rails/tasks/engine.rake"
load "rails/tasks/statistics.rake"

task :format do
  `bundle exec standardrb --fix`
  `bundle exec magic_frozen_string_literal .`
end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"

  # Running specific tests with line numbers, like with rails test, is not supported by default in rake.
  # By setting the TESTOPS env var we can however specify the name of a single test with underscores instead of spaces.
  # So run your single test by calling for ex:
  #
  # rake test /Users/sebastian/projects/cheddar/rails-twirp/test/ping_controller_test.rb "uncaught errors should bubble up to the test"

  file_name = ARGV[1]
  test_name = ARGV[2]&.tr(" ", "_")

  ENV["TESTOPTS"] = "--verbose"

  t.test_files = if file_name
    if test_name
      ENV["TESTOPTS"] += " --name=test_#{test_name}"
    end
    [file_name]
  else
    FileList["test/**/*_test.rb"]
  end
end

task default: ["app:test"]
