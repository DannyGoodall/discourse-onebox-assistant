# name: discourse-onebox-assistant
# about: provides alternative path for grabbing one-boxes when initial crawl fails
# version: 2.0
# authors: merefield

gem 'mime-types-data', '3.2019.1009'
gem 'mime-types', '3.3.1'
gem 'httparty', '0.17.3'

require 'net/http'

enabled_site_setting :onebox_assistant_enabled

after_initialize do
  Oneboxer.module_eval do

    def self.external_onebox(url)
      Discourse.cache.fetch(onebox_cache_key(url), expires_in: 1.day) do
        
        fd = FinalDestination.new(url,
                                ignore_redirects: ignore_redirects,
                                ignore_hostnames: blocked_domains,
                                force_get_hosts: force_get_hosts,
                                force_custom_user_agent_hosts: force_custom_user_agent_hosts,
                                preserve_fragment_url_hosts: preserve_fragment_url_hosts)
        uri = fd.resolve

        unless SiteSetting.onebox_assistant_always_use_proxy
          return blank_onebox if (uri.blank? && !SiteSetting.onebox_assistant_enabled) || blocked_domains.map { |hostname| uri.hostname.match?(hostname) }.any?
        else
          uri = url
        end

        options = {
          max_width: 695,
          sanitize_config: Onebox::DiscourseOneboxSanitizeConfig::Config::DISCOURSE_ONEBOX,
          hostname: GlobalSetting.hostname
        }

        options[:cookie] = fd.cookie if fd.cookie

        r = Onebox.preview(SiteSetting.onebox_assistant_enabled ? url : uri.to_s, options)

        { onebox: r.to_s, preview: r&.placeholder_html.to_s }
      end
    end
  end

  Onebox::Helpers.module_eval do

    IGNORE_CANONICAL_DOMAINS ||= ['www.instagram.com']

    class MyResty
      include HTTParty
      base_uri SiteSetting.onebox_assistant_api_base_address

      def preview(url)
        base_query=SiteSetting.onebox_assistant_api_base_query + url
        query = base_query + SiteSetting.onebox_assistant_api_options
        key = SiteSetting.onebox_assistant_api_key
        self.class.get(query, headers: {'x-api-key' => key})
      end
    end

    def self.fetch_html_doc(url, headers = nil)
      response = (fetch_response(url, nil, nil, headers) rescue nil)
      Rails.logger.error("fetch_html_doc: url = #{url}, headers = #{headers}, response = #{response.to_s}")

      if SiteSetting.onebox_assistant_always_use_proxy || (response.nil? && SiteSetting.onebox_assistant_enabled)
        retrieve_resty = MyResty.new
        Rails.logger.info "ONEBOX ASSIST: the url being sought from API is " + url
        initial_response = retrieve_resty.preview(url)
        Rails.logger.error("retrieve_resty/initial_response -> code = #{initial_response.code}, headers = #{initial_response.headers}.")
        response = initial_response[SiteSetting.onebox_assistant_api_page_source_field]
        if response.nil?
          Rails.logger.warning "ONEBOX ASSIST: the API returned nothing!!"
        end
      else
        Rails.logger.info "ONEBOX ASSIST: result from direct crawl, API was not called"
      end

      doc = Nokogiri::HTML(response)

      if !SiteSetting.onebox_assistant_enabled
        uri = URI(url)

        ignore_canonical_tag = doc.at('meta[property="og:ignore_canonical"]')
        should_ignore_canonical = IGNORE_CANONICAL_DOMAINS.map { |hostname| uri.hostname.match?(hostname) }.any?

        unless (ignore_canonical_tag && ignore_canonical_tag['content'].to_s == 'true') || should_ignore_canonical
          # prefer canonical link
          canonical_link = doc.at('//link[@rel="canonical"]/@href')
          if canonical_link && "#{URI(canonical_link).host}#{URI(canonical_link).path}" != "#{uri.host}#{uri.path}"
            response = (fetch_response(canonical_link, nil, nil, headers) rescue nil)
            doc = Nokogiri::HTML(response) if response
          end
        end
      end

      doc
    end

    def self.fetch_response(location, limit = nil, domain = nil, headers = nil)

      limit ||= 5
      limit = Onebox.options.redirect_limit if limit > Onebox.options.redirect_limit

      raise Net::HTTPError.new('HTTP redirect too deep', location) if limit == 0

      uri = Addressable::URI.parse(location)
      uri = Addressable::URI.join(domain, uri) if !uri.host

      result = StringIO.new
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.normalized_scheme == 'https') do |http|
        http.open_timeout = Onebox.options.connect_timeout
        http.read_timeout = Onebox.options.timeout
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # Work around path building bugs

        headers ||= {}

        if Onebox.options.user_agent && !headers['User-Agent']
          headers['User-Agent'] = Onebox.options.user_agent
        end

        request = Net::HTTP::Get.new(uri.request_uri, headers)
        start_time = Time.now

        size_bytes = Onebox.options.max_download_kb * 1024
        http.request(request) do |response|

          if cookie = response.get_fields('set-cookie')
            # HACK: If this breaks again in the future, use HTTP::CookieJar from gem 'http-cookie'
            # See test: it "does not send cookies to the wrong domain"
            redir_header = { 'Cookie' => cookie.join('; ') }
          end

          redir_header = nil unless redir_header.is_a? Hash

          code = response.code.to_i
          unless code === 200
            bletch_location = response.fetch('location', nil)
            Rails.logger.error("fetch_response: Code = #{code}, URL = #{uri}, Location = #{bletch_location}, user-agent = #{headers['User-Agent']} redir_header = #{redir_header}.")
            response.error! unless [301, 302, 303].include?(code)
            return fetch_response(
                response['location'],
                limit - 1,
                "#{uri.scheme}://#{uri.host}",
                redir_header
            )
          end

          response.read_body do |chunk|
            result.write(chunk)
            raise DownloadTooLarge.new if result.size > size_bytes
            raise Timeout::Error.new if (Time.now - start_time) > Onebox.options.timeout
          end

          return result.string
        end
      end
    end

  end
end
