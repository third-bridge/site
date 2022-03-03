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
(deftest warmup-test
  (submit-and-await!
   [
    [::xt/put
     {:xt/id "https://example.org/effects/put-user-dir-resource"
      ::site/type "Effect"
      ::pass/scope "userdir:write"
      ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
      ::pass/effect-args [{}]}]

    [:xtdb.api/put
     {:xt/id "https://example.org/people/alice",
      ::site/type "User"
      ::username "alice"
      :juxt.pass.alpha/ruleset "https://example.org/ruleset"}]

    [:xtdb.api/put
     {:xt/id "https://example.org/people/bob",
      ::site/type "User"
      ::username "bob"
      :juxt.pass.alpha/ruleset "https://example.org/ruleset"}]

    [::xt/put
     {:xt/id "https://example.org/acls/alice-can-create-user-dir-content"
      ::site/type "ACL"
      ::pass/subject "https://example.org/people/alice"
      ::pass/effect #{"https://example.org/effects/put-user-dir-resource"}
      ;; Is not constrained to a resource
      ::pass/resource nil #_"https://example.org/people/"
      }]])

  (let [check-acls
        (fn [db subject effect resource access-token-effective-scope]
          (xt/q
           db
           '{:find [acl]
             :where
             [
              [acl ::site/type "ACL"]
              [effect ::site/type "Effect"]
              [acl ::pass/effect effect]

              [effect ::pass/scope scope]
              [(contains? access-token-effective-scope scope)]

              (allowed? acl subject effect resource)]

             :rules [
                     [(allowed? acl subject effect resource)
                      [acl ::pass/subject subject]
                      [effect ::pass/resource-matches resource-regex]
                      [subject ::username username]
                      [(re-pattern resource-regex) resource-pattern]
                      [(re-matches resource-pattern resource) [_ user]]
                      [(= user username)]
                      ]]

             :in [subject effect resource access-token-effective-scope]}

           subject effect resource access-token-effective-scope))

        db (xt/db *xt-node*)]


    (are [subject effect resource access-token-effective-scope ok?]
        (let [actual (check-acls db subject effect resource access-token-effective-scope)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

        "https://example.org/people/alice"                    ; subject
        "https://example.org/effects/put-user-dir-resource"   ; effect
        "https://example.org/~alice/foo.txt"                  ; resource
        #{"userdir:write"} true )

    )

  )
