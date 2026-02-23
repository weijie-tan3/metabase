(ns metabase.driver.trino
  "Trino driver with support for OAuth 2.0, Azure Service Principal, and JWT authentication.
   Inherits core Trino SQL behavior from the starburst driver and adds authentication methods
   that the base starburst driver does not support."
  (:require
   [clojure.string :as str]
   [metabase.driver :as driver]
   [metabase.driver-api.core :as driver-api]
   [metabase.driver.sql-jdbc.common :as sql-jdbc.common]
   [metabase.driver.sql-jdbc.connection :as sql-jdbc.conn]
   [metabase.util.log :as log])
  (:import
   (java.net URI)
   (java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers)
   (java.time Duration)))

(set! *warn-on-reflection* true)

(driver/register! :trino, :parent :starburst)

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                    OAuth 2.0 Client Credentials Token Fetch                                    |
;;; +----------------------------------------------------------------------------------------------------------------+

(defn- url-encode-param
  "URL-encode a single parameter value for use in application/x-www-form-urlencoded body."
  ^String [^String s]
  (java.net.URLEncoder/encode s "UTF-8"))

(defn- build-token-request-body
  "Builds a URL-encoded form body for the OAuth 2.0 client credentials grant."
  [{:keys [oauth-client-id oauth-client-secret-value oauth-scope]}]
  (let [params (cond-> [["grant_type" "client_credentials"]
                        ["client_id" oauth-client-id]
                        ["client_secret" oauth-client-secret-value]]
                 (not (str/blank? oauth-scope))
                 (conj ["scope" oauth-scope]))]
    (str/join "&" (map (fn [[k v]] (str (url-encode-param k) "=" (url-encode-param v))) params))))

(defn- parse-json-token-response
  "Parses a JSON token response body and extracts the access_token field.
   Uses a simple regex-based approach to avoid adding a JSON dependency."
  ^String [^String body]
  (when-let [match (re-find #"\"access_token\"\s*:\s*\"([^\"]+)\"" body)]
    (second match)))

(defn- fetch-oauth-token!
  "Performs an OAuth 2.0 client credentials grant to obtain an access token.
   This supports Azure AD Service Principal, Okta, Keycloak, and other standard OAuth providers."
  [{:keys [oauth-token-url] :as details}]
  (let [body    (build-token-request-body details)
        client  (-> (HttpClient/newBuilder)
                    (.connectTimeout (Duration/ofSeconds 30))
                    (.build))
        request (-> (HttpRequest/newBuilder)
                    (.uri (URI/create oauth-token-url))
                    (.header "Content-Type" "application/x-www-form-urlencoded")
                    (.POST (HttpRequest$BodyPublishers/ofString body))
                    (.timeout (Duration/ofSeconds 30))
                    (.build))
        response (.send client request (HttpResponse$BodyHandlers/ofString))
        status   (.statusCode response)]
    (when-not (<= 200 status 299)
      (throw (ex-info (str "OAuth token request failed with HTTP status " status)
                      {:status status :body (.body response) :url oauth-token-url})))
    (let [token (parse-json-token-response (.body response))]
      (when (str/blank? token)
        (throw (ex-info "No access_token found in OAuth token response"
                        {:body (.body response) :url oauth-token-url})))
      (log/debugf "Successfully obtained OAuth access token from %s" oauth-token-url)
      token)))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                    Auth Provider Integration                                                   |
;;; +----------------------------------------------------------------------------------------------------------------+

(defmethod driver/incorporate-auth-provider-details :trino
  [_driver auth-provider auth-provider-response details]
  (case auth-provider
    (:oauth :azure-managed-identity)
    (let [{:keys [access_token]} auth-provider-response]
      (log/debug "Incorporating auth provider token into Trino connection details")
      (assoc details :trino/access-token access_token))
    ;; For other providers, merge the response into details
    (merge details auth-provider-response)))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                    Connection Details -> JDBC Spec                                             |
;;; +----------------------------------------------------------------------------------------------------------------+

(defn- resolve-access-token
  "Resolves the access token based on the configured auth method.
   - `:password` — no token, uses standard user/password
   - `:jwt` — uses the statically configured access token
   - `:oauth` — fetches a token using client credentials grant
   - Auth provider — uses the token injected by [[incorporate-auth-provider-details]]"
  [{:keys [auth-method access-token-value] :as details}]
  (let [method (keyword (or auth-method "password"))]
    (case method
      :jwt   (or access-token-value (:access-token details))
      :oauth (fetch-oauth-token! details)
      ;; password or auth-provider flow
      (or (:trino/access-token details) nil))))

(defn- trino-jdbc-url
  "Builds the JDBC URL for a Trino connection."
  [{:keys [host port catalog schema]
    :or   {host "localhost" port 8443 catalog ""}}]
  (let [db-path (cond
                  (str/blank? catalog) ""
                  (str/blank? schema)  catalog
                  :else                (str catalog "/" schema))]
    (str "jdbc:trino://" host ":" port "/" db-path)))

(defn- trino-auth-properties
  "Returns a map of JDBC properties for authentication based on the resolved token and config."
  [details]
  (let [token (resolve-access-token details)]
    (if-not (str/blank? token)
      {:accessToken token}
      (cond-> {}
        (:user details)     (assoc :user (:user details))
        (:password details) (assoc :password (:password details))))))

(defmethod sql-jdbc.conn/connection-details->spec :trino
  [_ {:keys [ssl prepared-optimized additional-options] :as details-map}]
  (let [jdbc-url   (trino-jdbc-url details-map)
        auth-props (trino-auth-properties details-map)
        base-props (merge {:classname   "io.trino.jdbc.TrinoDriver"
                           :subprotocol "trino"
                           :subname     (subs jdbc-url (count "jdbc:trino:"))
                           :SSL         (boolean ssl)
                           :source      (format "Metabase %s [%s]"
                                                (:tag driver-api/mb-version-info "")
                                                driver-api/local-process-uuid)}
                          auth-props
                          (when prepared-optimized
                            {:explicitPrepare "false"})
                          (when-let [roles (:roles details-map)]
                            (when-not (str/blank? roles)
                              {:roles (str "system:" roles)})))]
    (sql-jdbc.common/handle-additional-options
     (cond-> base-props
       (not (str/blank? additional-options))
       (assoc :additional-options additional-options)))))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                    Connection Validation                                                       |
;;; +----------------------------------------------------------------------------------------------------------------+

(defmethod driver/can-connect? :trino
  [driver details]
  ;; Delegate to the starburst parent for connection testing logic
  ((get-method driver/can-connect? :starburst) driver details))

(defmethod driver/display-name :trino
  [_]
  "Trino")
