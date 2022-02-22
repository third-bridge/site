;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.acl-test
  (:require
   [clojure.test :refer [deftest is are testing] :as t]
   [juxt.pass.alpha.authorization :as authz]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*
                           access-all-areas access-all-apis]]
   [jsonista.core :as json]
   [juxt.jinx.alpha.api :refer [schema validate]]
   [clojure.java.io :as io]
   [juxt.jinx.alpha :as jinx]
   [xtdb.api :as xt]))

(alias 'apex (create-ns 'juxt.apex.alpha))
(alias 'http (create-ns 'juxt.http.alpha))
(alias 'pick (create-ns 'juxt.pick.alpha))
(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(t/use-fixtures :each with-xt with-handler)

(defn fail [ex-data] (throw (ex-info "FAIL" ex-data)))

(defn check [db subject session action resource expected-count]
  (let [acls (authz/acls db subject session action resource)]
    (is (= expected-count (count acls)))
    (when-not (= expected-count (count acls))
      (fail {:session session
             :action action
             :resource resource
             :expected-count expected-count
             :actual-count (count acls)}))))

(defn list-resources [db subject session ruleset expected-resources]
  (let [acls (authz/list-resources db subject session ruleset)
        actual-resources (set (mapcat ::pass/resource acls))]
    (is (= expected-resources actual-resources))
    (when-not (= expected-resources actual-resources)
      (fail {:session session
             :expected-resources expected-resources
             :actual-resources actual-resources}))))

(defn get-subject [db session]
  (authz/get-subject-from-session db "https://example.org/ruleset" session))

(deftest scenario-1-test
  (submit-and-await!
   [
    [::xt/put
     {:xt/id "https://example.org/index"
      ::http/methods #{:get}
      ::http/content-type "text/html;charset=utf-8"
      ::http/content "Hello World!"
      ;; We'll define this lower down
      ::pass/ruleset "https://example.org/ruleset"}]

    ;; This is Alice.
    [::xt/put
     {:xt/id "https://example.org/people/alice"
      ::type "User"
      :juxt.pass.jwt/iss "https://example.org"
      :juxt.pass.jwt/sub "alice"
      }]

    ;; This is Bob.
    [::xt/put
     {:xt/id "https://example.org/people/bob"
      ::type "User"
      :juxt.pass.jwt/iss "https://example.org"
      :juxt.pass.jwt/sub "bob"}]

    [::xt/put
     {:xt/id "https://example.org/roles/manager"
      ::type "Role"}]

    ;; Bob's access will be via his 'manager' role.
    [::xt/put
     {:xt/id "https://example.org/roles/bob-is-manager"
      ::site/type "ACL"
      ::pass/subject "https://example.org/people/bob"
      ::pass/role "https://example.org/roles/manager"}]

    ;; This is Carl. Carl isn't a manager.
    [::xt/put
     {:xt/id "https://example.org/people/carl"
      ::type "User"
      :juxt.pass.jwt/iss "https://example.org"
      :juxt.pass.jwt/sub "carl"}]

    ;; A note on cacheing - each token can cache the resources it has access
    ;; to, keyed by action and transaction time. If a resource is updated, the
    ;; cache will fail. If an ACL is revoked, such that read access would no
    ;; longer be possible, the cache can still be used (avoiding the need to
    ;; detect changes to ACLs). See 'new enemy'
    ;; problem. https://duckduckgo.com/?t=ffab&q=authorization+%22new+enemy%22&ia=web

    [::xt/put
     {:xt/id "https://example.org/grants/alice-can-access-index"
      ::site/description "Alice is granted access to some resources"
      ::site/type "ACL"
      ::pass/subject "https://example.org/people/alice"

      ;; A resource can be any XT document, a superset of web resources. Common
      ;; authorization terminology uses the term 'resource' for anything that
      ;; can be protected.
      ::pass/resource #{"https://example.org/index"}
      ::pass/scope #{"read:index"}}]

    ;; TODO: Resource 'sets'

    [::xt/put
     {:xt/id "https://example.org/grants/managers-can-access-index"
      ::site/description "Managers are granted access to /index"
      ::site/type "ACL"

      ::pass/role "https://example.org/roles/manager"

      ;; A resource can be any XT document, a superset of web resources. Common
      ;; authorization terminology uses the term 'resource' for anything that
      ;; can be protected.
      ::pass/resource "https://example.org/index"
      ::pass/scope #{"read:index"}}]


    ;; TODO: Alice is the owner of a number of documents. Some she wants to
    ;; share some of these with Bob. Others she classifies INTERNAL (so visible
    ;; to all colleagues), and others she classifies PUBLIC, so visible to
    ;; anyone. The remainder are private and only she can access.

    [::xt/put
     {:xt/id "https://example.org/alice-docs/document-1"
      ::site/description "A document owned by Alice, to be shared with Bob"
      ::http/methods #{:get :put}
      ::http/content-type "text/html;charset=utf-8"
      ::http/content "My First Document"
      ::pass/ruleset "https://example.org/ruleset"}]

    [::xt/put
     {:xt/id "https://example.org/alice-docs/document-2"
      ::site/description "A document owned by Alice, not shared with anyone"
      ::http/methods #{:get :put}
      ::http/content-type "text/plain;charset=utf-8"
      ::http/content "My Second Document"
      ::pass/ruleset "https://example.org/ruleset"}]

    ;; An ACL that grants Alice ownership of a document
    [::xt/put
     {:xt/id "https://example.org/alice-owns-document-1"
      ::site/type "ACL"
      ::site/description "An ACL that grants Alice ownership of a document"
      ::pass/resource #{"https://example.org/alice-docs/document-1"}
      ::pass/owner "https://example.org/people/alice"
      ::pass/scope #{"read:document" "write:document"}
      }]

    ;; An ACL that grants Bob read access to Alice's document.
    [::xt/put
     {:xt/id "https://example.org/grants/bob-can-read-document-1"
      ::site/description "Bob is granted read access to Alice's document."
      ::site/type "ACL"
      ::pass/subject "https://example.org/people/bob"
      ::pass/resource #{"https://example.org/alice-docs/document-1"}
      ::pass/scope #{"read:document"}}]

    ;; Alice owns this whole directory
    [::xt/put
     {:xt/id "https://example.org/alice-docs/"
      ::site/description "A directory owned by Alice"
      ::http/methods #{:get}
      ::http/content-type "text/html;charset=utf-8"
      ::http/content "My Documents Directory"
      ::pass/ruleset "https://example.org/ruleset"}]
    [::xt/put
     {:xt/id "https://example.org/alice-owns-alice-docs"
      ::site/type "ACL"
      ::site/description "An ACL that grants Alice ownership of a directory"
      ::pass/resource #{"https://example.org/alice-docs/"}
      ::pass/owner "https://example.org/people/alice"
      ::pass/scope #{"read:directory-contents" "write:create-new-document"}
      }]

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
                 [subject :juxt.pass.jwt/iss iss]
                 [session :juxt.pass.jwt/sub sub]
                 [session :juxt.pass.jwt/iss iss]]])}]

    ;; We can now define the ruleset
    [::xt/put
     {:xt/id "https://example.org/ruleset"
      ::pass/rules ["https://example.org/rules/1"]}]

    ;; Establish a session for Alice.
    [::xt/put
     {:xt/id "urn:site:session:alice"
      :juxt.pass.jwt/sub "alice"
      :juxt.pass.jwt/iss "https://example.org"
      ::pass/scope #{"read:index"
                     "read:document" "write:document"
                     "read:directory-contents" "write:create-new-document"}}]

    ;; An access-token granted to an application on Alice's behalf, but
    ;; without as much scope.
    [::xt/put
     {:xt/id "urn:site:access-token:alice-without-write-document-scope"
      :juxt.pass.jwt/sub "alice"
      :juxt.pass.jwt/iss "https://example.org"
      ::pass/scope #{"read:index" "read:document"}}]

    [::xt/put
     {:xt/id "urn:site:session:bob"
      :juxt.pass.jwt/sub "bob"
      :juxt.pass.jwt/iss "https://example.org"
      ::pass/scope #{"read:index"
                     "read:document" "write:document"
                     "read:directory-contents" "write:create-new-document"}}]

    [::xt/put
     {:xt/id "urn:site:session:carl"
      :juxt.pass.jwt/sub "carl"
      :juxt.pass.jwt/iss "https://example.org"
      ::pass/scope #{"read:index"
                     "read:document" "write:document"
                     "read:directory-contents" "write:create-new-document"}}]])

  ;; Is subject allowed to do action to resource?
  ;; ACLs involved will include any limitations on actions

  ;; Which resources is subject allowed to do action on?
  ;; e.g. list of documents
  ;; This might be a solution to the n+1 problem in our graphql

  ;; Let's log in and create sessions

  (let [db (xt/db *xt-node*)
        session "urn:site:session:alice"
        subject (get-subject db session)]

    (when-not (= subject "https://example.org/people/alice") (fail {:subject subject}))

    (check db subject session "read:index" "https://example.org/index" 1)


    ;; Fuzz each of the parameters to check that the ACL fails
    (check db nil nil "read:index" "https://example.org/index" 0)
    (check db subject session "read:index" "https://example.org/other-page" 0)
    (check db subject session "write:index" "https://example.org/index" 0)

    ;; Bob can read index
    (check db "https://example.org/people/bob" "urn:site:session:bob" "read:index" "https://example.org/index" 1)

    ;; But Carl cannot
    (check db "https://example.org/people/carl" "urn:site:session:carl" "read:index" "https://example.org/index" 0)

    ;; Which resources can Alice access, given session scope?
    (list-resources
     db subject session "https://example.org/ruleset"
     #{"https://example.org/index" "https://example.org/alice-docs/" "https://example.org/alice-docs/document-1"})

    ;; TODO: Alice sets up her own home-page, complete with an API for a test project
    ;; she's working on.

    ;; Alice can read her own documents, on account of ::pass/owner
    (check db subject session "read:document" "https://example.org/alice-docs/document-1" 1)

    ;; Alice can write her own documents, on account of ::pass/owner
    (check db subject session "write:document" "https://example.org/alice-docs/document-1" 1)

    ;; When Alice authorizes an application to use an access-token with
    ;; read:document scope, the application can read the document.
    (check db subject "urn:site:access-token:alice-without-write-document-scope" "read:document" "https://example.org/alice-docs/document-1" 1)
    ;; But when the application attempts to overwrite a document belonging to
    ;; Alice, it is denied.
    (check db subject "urn:site:access-token:alice-without-write-documents-scope" "write:document" "https://example.org/alice-docs/document-1" 0)

    ;; Alice wants to create a new document, can she? We check the parent
    ;; directory, which should exist and be owned by Alice.
    (check db subject session "write:create-new-document" "https://example.org/alice-docs/" 1)

    ;; Bob accesses Alice's documents.
    (let [subject "https://example.org/people/bob"
          session "urn:site:session:bob"]
      (check db subject session "read:document" "https://example.org/alice-docs/document-1" 1)
      (check db subject session "read:document" "https://example.org/alice-docs/document-2" 0))

    ;; This means that Alice should be able to create an ACL for Bob, which see
    ;; owns. But she can only create an ACL that references documents she owns.

    ;; TODO: Add resources to represent Alice, Bob and Carl, as subjects.

    {:status :ok :message "All tests passed"}
    ))

#_((t/join-fixtures [with-xt with-handler])
 )


;; Create a non-trivial complex scenario which contains many different
;; characters and rulesets.

;; TODO: INTERNAL classification
;; TODO: User content: e.g. https://example.org/~alice
;; TODO: Consent-based access control
;; TODO: Extend to GraphQL

;; TODO: A subject using an application that is scope constrained
