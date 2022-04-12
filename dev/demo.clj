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
  ;; tag::put-repl-user![]
  (put! {:xt/id (me)})
  ;; end::put-repl-user![]
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
          [permission :juxt.pass.alpha/subject subject]]]})
     ;; end::create-action-put-immutable-public-resource![]
     ))))

(defn demo-grant-permission-to-call-action-put-immutable-public-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-call-action-put-immutable-public-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-immutable-public-resource"
       :juxt.pass.alpha/subject "urn:site:subjects:repl"
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
          [permission :juxt.pass.alpha/subject subject]]]})
     ;; end::create-action-put-immutable-private-resource![]
     ))))

(defn demo-grant-permission-to-put-immutable-private-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-put-immutable-private-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-immutable-private-resource"
       :juxt.pass.alpha/subject "urn:site:subjects:repl"
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
         '[permission :juxt.pass.alpha/resource resource]
         ['permission :juxt.pass.alpha/action "https://site.test/actions/get-private-resource"]
         ['subject :xt/id]]]})
     ;; end::create-action-get-private-resource[]
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
          [permission :juxt.pass.alpha/subject subject]]]})
     ;; end::create-action-put-error-resource![]
     ))))

(defn demo-grant-permission-to-put-error-resource! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::grant-permission-to-put-error-resource![]
     (grant-permission!
      {:xt/id "https://site.test/permissions/repl/put-error-resource"
       :juxt.pass.alpha/subject "urn:site:subjects:repl"
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
  (demo-put-unauthorized-error-representation-for-html!)

  )

(defn demo-put-unauthorized-error-representation-for-html-2! []
  (eval
   (substitute-actual-base-uri
    (quote
     ;; tag::put-unauthorized-error-representation-for-html-2![]
     (do
       (do-action
        "https://site.test/actions/put-immutable-public-resource"
        {:xt/id "https://site.test/_site/errors/unauthorized.html"
         :juxt.site.alpha/variant-of "https://site.test/_site/errors/unauthorized"
         :juxt.http.alpha/content-type "text/html;charset=utf-8"
         :juxt.http.alpha/content "<!DOCTYPE html><html><head><meta http-equiv='Refresh' content='0; url='https://site.test/_site/openid/auth0-site-test/login'/></head><body><h1>Unauthorized</h1></body></html>"})

       (do-action
        "https://site.test/actions/put-immutable-public-resource"
        {:xt/id "https://site.test/_site/errors/unauthorized.html"
         :juxt.site.alpha/variant-of "https://site.test/_site/errors/unauthorized"
         :juxt.http.alpha/content-type "text/html;charset=utf-8"
         :juxt.http.alpha/content "<!DOCTYPE html><html><head><meta http-equiv='Refresh' content='0; url='https://site.test/_site/openid/auth0-site-test/login'/></head><body><h1>Unauthorized</h1></body></html>"}))
     ;; end::put-unauthorized-error-representation-for-html-2![]
     )))
  )
