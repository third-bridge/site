;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are testing use-fixtures] :as t]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; As a warmup, let's start with some contrived data and demonstrate how
;; authorization works in Site.

;; In Site's authorization system, a subject might cause an effect on a resource
;; (which would change it in some way). The authorization system must first
;; check that the subject (user) is allowed to cause a given effect on the
;; resource.

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/effects/resources and
;; scopes.

(defn check-acls
  [db subject effect resource access-token-effective-scope rules]
  (xt/q
   db
   {:find '[acl]
    :where
    '[
      [acl ::site/type "ACL"]
      [effect ::site/type "Effect"]
      [acl ::pass/effect effect]

      [effect ::pass/scope scope]
      [(contains? access-token-effective-scope scope)]

      (allowed? acl subject effect resource)]

    :rules rules

    :in '[subject effect resource access-token-effective-scope]}

   subject effect resource access-token-effective-scope))

(def ALICE
  {:xt/id "https://example.org/people/alice",
   ::site/type "User"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob",
   ::site/type "User"
   ::username "bob"})

(def CARL
  {:xt/id "https://example.org/people/carl",
   ::site/type "User"
   ::username "carl"})

(def PUT_USER_DIR
  {:xt/id "https://example.org/effects/put-user-dir"
   ::site/type "Effect"
   ::pass/scope "userdir:write"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/effect-args [{}]})

(def ALICE_CAN_PUT_USER_DIR_CONTENT
  {:xt/id "https://example.org/acls/alice-can-put-user-dir-content"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/alice"
   ::pass/effect #{"https://example.org/effects/put-user-dir"}
   ;; Is not constrained to a resource
   ::pass/resource nil})

(def BOB_CAN_PUT_USER_DIR_CONTENT
  {:xt/id "https://example.org/acls/bob-can-put-user-dir-content"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/bob"
   ::pass/effect #{"https://example.org/effects/put-user-dir"}
   ::pass/resource nil})

(deftest user-dir-test
  (submit-and-await!
   [
    [:xtdb.api/put ALICE]
    [:xtdb.api/put BOB]
    [:xtdb.api/put CARL]
    [::xt/put PUT_USER_DIR]
    [::xt/put ALICE_CAN_PUT_USER_DIR_CONTENT]
    [::xt/put BOB_CAN_PUT_USER_DIR_CONTENT]])

  (let [rules
        '[
          [(allowed? acl subject effect resource)
           [acl ::pass/subject subject]
           [effect ::pass/resource-matches resource-regex]
           [subject ::username username]
           [(re-pattern resource-regex) resource-pattern]
           [(re-matches resource-pattern resource) [_ user]]
           [(= user username)]
           ]]


        db (xt/db *xt-node*)]

    (are [subject effect resource access-token-effective-scope ok?]
        (let [actual (check-acls db subject effect resource access-token-effective-scope rules)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can put a file to her user directory
        "https://example.org/people/alice"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~alice/foo.txt"
        #{"userdir:write" "other:scope"} true

        ;; Alice can't put a file to her user directory if the scope doesn't allow
        ;; it (either the application is itself constrained, or she hasn't
        ;; authorized the userdir:write scope on the application)
        "https://example.org/people/alice"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~alice/foo.txt"
        #{"other:scope"} false

        ;; Alice can't put a file to Bob's user directory
        "https://example.org/people/alice"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~bob/foo.txt"
        #{"userdir:write"} false

        ;; Alice can't put a file outside her user directory
        "https://example.org/people/alice"
        "https://example.org/effects/put-user-dir"
        "https://example.org/index.html"
        #{"userdir:write"} false

        ;; Bob can put a file to his user directory
        "https://example.org/people/bob"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~bob/foo.txt"
        #{"userdir:write"} true

        ;; Bob can't put a file to Alice's directory
        "https://example.org/people/bob"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~alice/foo.txt"
        #{"userdir:write"} false

        ;; Carl cannot put a file to his user directory, as he hasn't been
        ;; granted the put-user-dir effect.
        "https://example.org/people/carl"
        "https://example.org/effects/put-user-dir"
        "https://example.org/~carl/foo.txt"
        #{"userdir:write"} false)))
