;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.acl-test-2
  (:require
   [clojure.test :refer [deftest is are testing] :as t]
   [juxt.pass.alpha.authorization :as authz]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'apex (create-ns 'juxt.apex.alpha))
(alias 'http (create-ns 'juxt.http.alpha))
(alias 'pick (create-ns 'juxt.pick.alpha))
(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

;; As above but building up from a smaller seed.
((t/join-fixtures [with-xt with-handler])
 (fn []
   (submit-and-await!
    [
     [::xt/put
      {:xt/id "https://example.org/people/sue"
       ::type "User"
       :juxt.pass.jwt/sub "sue"}]

     [::xt/put
      {:xt/id "https://example.org/rules/1"
       ::site/description "Allow read access of resources to granted subjects"
       ::pass/rule-content
       (pr-str '[[(check acl subject session action resource)
                  [acl ::site/type "ACL"]
                  [acl ::pass/resource resource]
                  (granted? acl subject)
                  [acl ::pass/scope action]
                  [session ::pass/scope action]]

                 ;; An ACL that establishes ownership
                 [(granted? acl subject)
                  [acl ::pass/owner subject]]

                 ;; An ACL granted to the subject directly for a given action
                 [(granted? acl subject)
                  [acl ::pass/subject subject]]

                 ;; An ACL granted on a role that the subject has
                 [(granted? acl subject)
                  [acl ::pass/role role]
                  [role ::type "Role"]
                  [role-membership ::site/type "ACL"]
                  [role-membership ::pass/subject subject]
                  [role-membership ::pass/role role]]

                 [(list-resources acl subject session)
                  [acl ::pass/resource resource]
                  [acl ::pass/scope action]
                  [session ::pass/scope action]
                  (granted? acl subject)]

                 [(get-subject-from-session session subject)
                  [subject ::type "User"]
                  [subject :juxt.pass.jwt/sub sub]
                  [session :juxt.pass.jwt/sub sub]]])}]

     ;; We can now define the ruleset
     [::xt/put
      {:xt/id "https://example.org/ruleset"
       ::pass/rules ["https://example.org/rules/1"]}]

     ;; TODO: Need a ruleset to allow Sue to create Alice
     ])

   (let [admin-client
         (into
          {::pass/name "Site Admininistration"
           ;; If specified (and it must be currently), ::pass/scope overrides
           ;; the subject's default scope.
           ::pass/scope
           #{"read:index"
             "read:document" "write:document"
             "read:directory-contents" "write:create-new-document"}}
          (authz/make-application {::site/base-uri "https://example.org"}))

         guest-client
         (into
          {::pass/name "Guest Access"
           ::pass/scope #{"read:index" "read:document"}}
          (authz/make-application
           {::site/base-uri "https://example.org"}))

         _ (submit-and-await!
            [
             [::xt/put admin-client]
             [::xt/put guest-client]])

         ;; All access to any API is via an access-token.
         ;; Having chosen the client application, we acquire an access-token.

         access-token
         (into
          (authz/make-access-token (:xt/id admin-client))
          {
           ;; We just merge in the id claims we know, keep this flat.
           :juxt.pass.jwt/iss "https://example.org"
           :juxt.pass.jwt/sub "sue"
           ;; If specified (and it must be currently), ::pass/scope overrides
           ;; the default application scope
           ::pass/scope #{"read:document"}
           })

         ;; An access token must exist in the database, linking to the application,
         ;; the subject and its own granted scopes. The actual scopes are the
         ;; intersection of all three.

         _ (submit-and-await!
            [[::xt/put access-token]])]


     ;; The access-token links to the application, the subject and its own
     ;; scopes. The overall scope of the request is ascertained at each and
     ;; every request.
     access-token

     ;; Perf: The actual scope should be determined at request time and bound to
     ;; the request.

     ;; If accessing the API directly with a browser, the access-token is
     ;; generated and stored in the session (accessed via the cookie rather than
     ;; the Authorization header).

     ;; The bin/site tool might have to be configured with the client-id of the
     ;; 'Admin App'.

     ;; Imagine

     ;; TODO: Sue creates Alice, with Alice's rights



     #_(let [db (xt/db *xt-node*)]

         ;;







         ;;(check db subject session "read:index" "https://example.org/index" 1)

         ;;{:status :ok :message "All tests passed"}
         ))))
