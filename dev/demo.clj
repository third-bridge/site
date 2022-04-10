;; Copyright © 2022, JUXT LTD.

(ns demo
  (:require
   [juxt.site.alpha.repl :refer :all]
   [juxt.http.alpha :as-alias http]
   [juxt.pass.alpha :as-alias pass]
   [clojure.walk :refer [postwalk]]
   [clojure.string :as str]))

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

(defn demo-bootstrap-resources! []
  (demo-create-action-put-immutable-public-resource!)
  (demo-grant-permission-to-call-action-put-immutable-public-resource!)
  (demo-create-action-get-public-resource!)
  (demo-grant-permission-to-call-get-public-resource!)
  (demo-create-action-put-immutable-private-resource!)
  (demo-grant-permission-to-put-immutable-private-resource!)
  (demo-create-action-get-private-resource!)
  (demo-create-immutable-private-resource!))
