require "./spec_helper"

# The layout vars a full page render needs (see Server#base_vars).
private def layout_vars(**extra)
  Crinja.variables({
    "site_name"    => "Specsite",
    "color_mode"   => "auto",
    "version"      => Clpaste::VERSION,
    "git_sha"      => Clpaste::GIT_SHA,
    "show_version" => true,
    "id_digits"    => 9,
    "title"        => "T",
    "heading"      => "H",
    "message"      => "Spec message body",
  }.merge(extra.to_h.transform_keys(&.to_s)))
end

describe Clpaste::Views do
  it "renders built-in templates without a theme" do
    views = Clpaste::Views.new("")
    html = views.render("message.html", layout_vars)
    html.should contain(%(class="navbar-brand"))
    html.should contain("Specsite")
  end

  it "lets a theme layout extend the built-in one and override blocks" do
    dir = File.join(SCRATCH, "theme-#{Random::Secure.hex(4)}")
    Dir.mkdir_p(dir)
    File.write(File.join(dir, "layout.html"), <<-HTML)
      {% extends "builtin/layout.html" %}
      {% block head_extra %}<link rel="stylesheet" href="/static/extra.css">{% endblock %}
      {% block navbar_class %}navbar custom-navbar{% endblock %}
      {% block navbar_attrs %} data-bs-theme="dark"{% endblock %}
      {% block navbar_brand %}<a class="navbar-brand" href="/"><img src="/static/logo.svg" alt="">{{ site_name }}</a>{% endblock %}
      HTML

    views = Clpaste::Views.new(dir)
    html = views.render("message.html", layout_vars)
    html.should contain(%(href="/static/extra.css"))
    html.should contain(%(<nav class="navbar custom-navbar" data-bs-theme="dark">))
    html.should contain(%(<img src="/static/logo.svg"))
    html.should contain("Specsite")          # non-overridden parts still render
    html.should contain("Spec message body") # the page's own content block too
    html.should_not contain("bg-body-tertiary")
  end

  it "serves theme static files over built-ins" do
    dir = File.join(SCRATCH, "theme-#{Random::Secure.hex(4)}")
    Dir.mkdir_p(File.join(dir, "static"))
    File.write(File.join(dir, "static", "app.css"), "/* themed */")
    File.write(File.join(dir, "static", "logo.svg"), "<svg/>")

    views = Clpaste::Views.new(dir)
    must(views.static("app.css"))[0].should eq("/* themed */")
    must(views.static("logo.svg")).should eq({"<svg/>", "image/svg+xml"})
    must(views.static("bootstrap.min.css"))[0].should contain("Bootstrap")
  end
end
