;; Copyright © 2022, JUXT LTD.

(ns demo
  (:require
   [juxt.site.alpha.repl :refer :all]
   [juxt.http.alpha :as-alias http]
   [juxt.pass.alpha :as-alias pass]
   [juxt.site.alpha :as-alias site]
   [clojure.walk :refer [postwalk]]
   [clojure.string :as str]
   [malli.core :as m]))

(defn demo-install-do-action-fn! []
  ;; tag::install-do-action-fn![]
  (install-do-action-fn!)
  ;; end::install-do-action-fn![]
  )

(defn demo-put-repl-user! []
  ;; tag::install-repl-user![]
  (install-repl-user!)
  ;; end::install-repl-user![]
  )

(defn demo-install-create-action! []
  ;; tag::install-create-action![]
  (install-create-action!)
  ;; end::install-create-action![]
  )

(defn demo-permit-create-action! []
  ;; tag::permit-create-action![]
  (permit-create-action!)
  ;; end::permit-create-action![]
  )

(defn demo-install-grant-permission-action! []
  ;; tag::install-grant-permission-action![]
  (install-grant-permission-action!)
  ;; end::install-grant-permission-action![]
  )

(defn demo-permit-grant-permission-action! []
  ;; tag::permit-grant-permission-action![]
  (permit-grant-permission-action!)
  ;; end::permit-grant-permission-action![]
  )

(defn demo-bootstrap-actions! []
  (demo-install-do-action-fn!)
  (demo-put-repl-user!)
  (demo-install-create-action!)
  (demo-permit-create-action!)
  (demo-install-grant-permission-action!)
  (demo-permit-grant-permission-action!))

(defn substitute-actual-base-uri [form]
  (postwalk
   (fn [s]
     (cond-> s
       (string? s) (str/replace "https://site.test" (base-uri)))
     )
   form))

(defn demo-create-action-put-immutable-public-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-put-immutable-public-resource![]
     (create-action!
      {:xt/id "https://site.test/actions/put-immutable-public-resource"
       :juxt.pass.alpha/scope "write:resource" ; <1>

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/.*"]]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.process/update-in
         [0] 'merge
         {::http/methods                 ; <2>
          {:get {::pass/actions #{"https://site.test/actions/get-public-resource"}}
           :head {::pass/actions #{"https://site.test/actions/get-public-resource"}}
           :options {::pass/actions #{"https://site.test/actions/get-options"}}}}]

        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource) ; <3>
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-action-put-immutable-public-resource![]
     ))))

(defn demo-grant-permission-to-call-action-put-immutable-public-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-action-put-immutable-public-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-immutable-public-resource"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-immutable-public-resource"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-call-action-put-immutable-public-resource![]
     ))))

(defn demo-create-action-get-public-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-get-public-resource![]
     (create-action!
      {:xt/id "https://site.test/actions/get-public-resource"
       :juxt.pass.alpha/scope "read:resource" ; <1>

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :xt/id "https://site.test/permissions/public-resources-to-all"] ; <2>
          ]]})
     ;; end::create-action-get-public-resource![]
     ))))

(defn demo-grant-permission-to-call-get-public-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-get-public-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/public-resources-to-all"
       :juxt.pass.alpha/action #{"https://site.test/actions/get-public-resource"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-call-get-public-resource![]
     ))))

(defn demo-create-hello-world-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-hello-world-resource![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/hello"
       :juxt.http.alpha/content-type "text/plain"
       :juxt.http.alpha/content "Hello World!\r\n"})
     ;; end::create-hello-world-resource![]
     ))))

(defn demo-create-hello-world-html-representation! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-hello-world-html-representation![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/hello.html" ; <1>
       :juxt.http.alpha/content-type "text/html;charset=utf-8" ; <2>
       :juxt.http.alpha/content "<h1>Hello World!</h1>\r\n" ; <3>
       :juxt.site.alpha/variant-of "https://site.test/hello" ; <4>
       })
     ;; end::create-hello-world-html-representation![]
     ))))


;; Templating

(defn demo-create-put-template-action! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-put-template-action![]
     (create-action!
      {:xt/id "https://site.test/actions/put-template"
       :juxt.pass.alpha/scope "write:resource"

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/templates/.*"]]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.process/update-in
         [0] 'merge
         {::http/methods {}}]
        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-put-template-action![]
     ))))

(defn demo-grant-permission-to-call-action-put-template! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-action-put-template![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-template"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-template"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-call-action-put-template![]
     ))))

(defn demo-create-hello-world-html-template! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-hello-world-html-template![]
     (do-action
      "https://site.test/actions/put-template"
      {:xt/id "https://site.test/templates/hello.html"
       :juxt.http.alpha/content-type "text/html;charset=utf-8"
       :juxt.http.alpha/content "<h1>Hello {audience}!</h1>\r\n"})
     ;; end::create-hello-world-html-template![]
     ))))

(defn demo-create-hello-world-with-html-template! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-hello-world-with-html-template![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/hello-with-template.html"
       :juxt.site.alpha/template "https://site.test/templates/hello.html"
       })
     ;; end::create-hello-world-with-html-template![]
     ))))


;; Identities

(defn demo-create-action-put-identity! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-put-identity![]
     (create-action!
      {:xt/id "https://site.test/actions/put-identity"
       :juxt.pass.alpha/scope "write:identity"

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/.*"]]
         [:juxt.site.alpha/type [:= "Identity"]]
         [:juxt.pass.jwt/iss [:re "https://.+"]]
         [:juxt.pass.jwt/sub [:string {:min 1}]]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.process/update-in
         [0] 'merge
         {:juxt.site.alpha/type "Identity"
          :juxt.http.alpha/methods
          {:get {:juxt.pass.alpha/actions #{"https://site.test/actions/get-identity"}}
           :head {:juxt.pass.alpha/actions #{"https://site.test/actions/get-identity"}}
           :options {}}}]
        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-action-put-identity![]
     ))))

(defn demo-grant-permission-to-call-action-put-identity! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-action-put-identity![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-identity"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-identity"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-call-action-put-identity![]
     ))))

(defn demo-create-action-get-identity! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-get-identity![]
     (create-action!
      {:xt/id "https://site.test/actions/get-identity"
       :juxt.pass.alpha/scope "read:identity"

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]
          ]]})
     ;; end::create-action-get-identity![]
     ))))

(defn demo-create-identity! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-identity![]
     (do-action
      "https://site.test/actions/put-identity"
      {:xt/id "https://site.test/~mal"
       :code "mal"
       :juxt.pass.jwt/iss "https://juxt.eu.auth0.com/"
       :juxt.pass.jwt/sub "github|163131"
       :juxt.http.alpha/content "Malcolm Sparks"
       :juxt.http.alpha/content-type "text/plain"})
     ;; end::create-identity![]
     ))))

(defn demo-grant-permission-for-mal-to-get-mal! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-for-mal-to-get-mal![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/mal/get-identity"
       :juxt.pass.alpha/identity "https://site.test/~mal"
       :juxt.pass.alpha/action #{"https://site.test/actions/get-identity"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-for-mal-to-get-mal![]
     )))
  )

;; We don't need to show the login page
#_(defn demo-put-login-page! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::put-login-page![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/login"
       :juxt.http.alpha/content-type "text/html;charset=utf-8"
       :juxt.http.alpha/content (slurp "dev/login.html")}))
    ;; end::put-login-page![]
    )))

;; APIs

(defn demo-create-action-put-api-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-put-api-resource![]
     (create-action!
      {:xt/id "https://site.test/actions/put-api-resource"
       :juxt.pass.alpha/scope "write:api"

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/.*"]]
         [:juxt.http.alpha/methods
          [:map-of
           :keyword
           [:map
            [:juxt.pass.alpha/actions [:set [:string]]]]]]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-action-put-api-resource![]
     ))))

(defn demo-grant-permission-to-call-action-put-api-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-action-put-api-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-api-resource"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-api-resource"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-call-action-put-api-resource![]
     ))))

;; API example

(defn demo-create-action-list-identities! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-list-identities![]
     (create-action!
      {:xt/id "https://site.test/actions/list-identities"
       :juxt.pass.alpha/scope "read:identity"

       :juxt.pass.alpha/pull '[*]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [action :xt/id "https://site.test/actions/list-identities"]
          [resource :juxt.site.alpha/type "Identity"]
          [permission :juxt.pass.alpha/action action]]]})
     ;; end::create-action-list-identities![]
     ))))

(defn demo-grant-permission-to-list-identities! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-list-identities![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/list-identities"
       ;; Comment out just to make public
       ;;:juxt.pass.alpha/subject "urn:site:subjects:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/list-identities"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-list-identities![]
     ))))

;; Create an action to invoke a 'read' API

(defn demo-create-action-invoke-read-api! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-invoke-read-api![]
     (create-action!
      {:xt/id "https://site.test/actions/invoke-read-api"
       :juxt.pass.alpha/scope "read:resource"
       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [action :xt/id "https://site.test/actions/invoke-read-api"]
          [permission :juxt.pass.alpha/action action]]]})
     ;; end::create-action-invoke-read-api![]
     ))))

;; Grant everyone permission to call an API

(defn demo-grant-permission-to-invoke-read-api! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-invoke-read-api![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/invoke-read-api"
       :juxt.pass.alpha/action #{"https://site.test/actions/invoke-read-api"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-invoke-read-api![]
     ))))

;; Connect up an API

(defn demo-create-list-users-api! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-list-users-api![]
     (do-action
      "https://site.test/actions/put-api-resource"
      {:xt/id "https://site.test/users"
       :juxt.http.alpha/content-type "text/plain"
       :juxt.http.alpha/methods
       {:get
        {:juxt.pass.alpha/actions
         #{"https://site.test/actions/invoke-read-api"}
         #_:juxt.pass.alpha/actions
         #_#{"https://site.test/actions/list-identities"}}}})
     ;; end::create-list-users-api![]
     ))))

;; Why 401? where is this coming from? perhaps if we gave permission to everyone to list-identities?

;; Perhaps do private resources and authentication first

;; github|163131 needs


;; Private resources and authentication

(defn demo-create-action-put-immutable-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-put-immutable-private-resource![]
     (create-action!
      {:xt/id "https://site.test/actions/put-immutable-private-resource"
       :juxt.pass.alpha/scope "write:resource"

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/.*"]]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.process/update-in
         [0] 'merge
         {::http/methods
          {:get {::pass/actions #{"https://site.test/actions/get-private-resource"}}
           :head {::pass/actions #{"https://site.test/actions/get-private-resource"}}
           :options {::pass/actions #{"https://site.test/actions/get-options"}}}}]

        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-action-put-immutable-private-resource![]
     ))))

(defn demo-grant-permission-to-put-immutable-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-put-immutable-private-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-immutable-private-resource"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-immutable-private-resource"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-put-immutable-private-resource![]
     ))))

(defn demo-create-action-get-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-get-private-resource[]
     (create-action!
      {:xt/id "https://site.test/actions/get-private-resource"
       :juxt.pass.alpha/scope "read:resource"

       :juxt.pass.alpha/rules
       [
        ['(allowed? permission subject action resource)
         ['permission :juxt.pass.alpha/action "https://site.test/actions/get-private-resource"]
         ['subject :juxt.pass.alpha/identity]]]})
     ;; end::create-action-get-private-resource[]
     ))))

(defn demo-grant-permission-to-get-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-get-private-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/any-subject/get-private-resource"
       :juxt.pass.alpha/action "https://site.test/actions/get-private-resource"
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-get-private-resource![]
     ))))

(defn demo-create-immutable-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-immutable-private-resource![]
     (do-action
      "https://site.test/actions/put-immutable-private-resource"
      {:xt/id "https://site.test/private.html"
       :juxt.http.alpha/content-type "text/html;charset=utf-8"
       :juxt.http.alpha/content "<p>This is a protected message that those authorized are allowed to read.</p>"})
     ;; end::create-immutable-private-resource![]
     ))))

(defn demo-create-action-put-error-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::create-action-put-error-resource![]
     (create-action!
      {:xt/id "https://site.test/actions/put-error-resource"
       :juxt.pass.alpha/scope "write:resource"

       :juxt.pass.alpha.malli/args-schema
       [:tuple
        [:map
         [:xt/id [:re "https://site.test/_site/errors/[a-z\\-]{3,}"]]
         [:juxt.site.alpha/type [:= "ErrorResource"]]
         [:ring.response/status :int]]]

       :juxt.pass.alpha/process
       [
        [:juxt.pass.alpha.malli/validate]
        [:xtdb.api/put]]

       :juxt.pass.alpha/rules
       '[
         [(allowed? permission subject action resource)
          [permission :juxt.pass.alpha/identity i]
          [subject :juxt.pass.alpha/identity i]]]})
     ;; end::create-action-put-error-resource![]
     ))))

(defn demo-grant-permission-to-put-error-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-put-error-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-error-resource"
       :juxt.pass.alpha/identity "urn:site:identities:repl"
       :juxt.pass.alpha/action #{"https://site.test/actions/put-error-resource"}
       :juxt.pass.alpha/purpose nil})
     ;; end::grant-permission-to-put-error-resource![]
     ))))

(defn demo-put-unauthorized-error-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::put-unauthorized-error-resource![]
     (do-action
      "https://site.test/actions/put-error-resource"
      {:xt/id "https://site.test/_site/errors/unauthorized"
       :juxt.site.alpha/type "ErrorResource"
       :ring.response/status 401})
     ;; end::put-unauthorized-error-resource![]
     ))))

#_{:xt/id "{{base-uri}}/_site/errors/unauthorized.html"
 :juxt.http.alpha/methods #{:get :head :options}
 :juxt.site.alpha/variant-of "{{base-uri}}/_site/errors/unauthorized"
 :juxt.site.alpha/type "TemplatedRepresentation"
 :juxt.site.alpha/template "{{base-uri}}/_site/templates/unauthorized.html"
 :juxt.site.alpha/template-model juxt.pass.alpha.authentication/unauthorized-template-model
 :juxt.pass.alpha/classification "PUBLIC"}

(defn demo-put-unauthorized-error-representation-for-html! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::put-unauthorized-error-representation-for-html![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/_site/errors/unauthorized.html"
       :juxt.site.alpha/variant-of "https://site.test/_site/errors/unauthorized"
       :juxt.http.alpha/content-type "text/html;charset=utf-8"
       :juxt.http.alpha/content "<h1>Unauthorized</h1>\r\n"})
     ;; end::put-unauthorized-error-representation-for-html![]
     )))
  )

(defn demo-bootstrap-resources! []
  (demo-create-action-put-immutable-public-resource!)
  (demo-grant-permission-to-call-action-put-immutable-public-resource!)
  (demo-create-action-get-public-resource!)
  (demo-grant-permission-to-call-get-public-resource!)

  (demo-create-action-put-immutable-private-resource!)
  (demo-grant-permission-to-put-immutable-private-resource!)
  (demo-create-action-get-private-resource!)

  ;; This is 'just' an example showing how to create a /privte.html resource. We
  ;; don't want this resource part of every install!
  ;; (demo-create-immutable-private-resource!)

  (demo-create-action-put-error-resource!)
  (demo-grant-permission-to-put-error-resource!)
  (demo-put-unauthorized-error-resource!)
  (demo-put-unauthorized-error-representation-for-html!))

(defn demo-put-unauthorized-error-representation-for-html-with-login-link! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::put-unauthorized-error-representation-for-html-with-login-link![]
     (do-action
      "https://site.test/actions/put-immutable-public-resource"
      {:xt/id "https://site.test/_site/errors/unauthorized.html"
       :juxt.site.alpha/variant-of "https://site.test/_site/errors/unauthorized"
       :juxt.http.alpha/content-type "text/html;charset=utf-8"
       :juxt.http.alpha/content (slurp "dev/unauthorized.html")})
     ;; end::put-unauthorized-error-representation-for-html-with-login-link![]
     ))))
