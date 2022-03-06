;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.v3.authorization-explainer-test
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

;; In Site's authorization system, a subject might cause an action on a resource
;; (which might cause it to change in some way). The authorization system must
;; first check that the subject (user) is allowed to cause a given action on the
;; resource.

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/actions/resources.

(defn check-permissions
  "Given a subject, an action and resource, return all related permissions."
  [db subject actions resource rules]
  (xt/q
   db
   {:find '[permission]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [(contains? actions action)]
      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions resource]}

   subject actions resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db subject actions rules]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [(contains? actions action)]

      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions]}

   subject actions))

(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db resource actions rules]
  (->> (xt/q
        db
        {:find '[subject action]
         :keys '[subject action]
         :where
         '[
           [permission ::site/type "Permission"]
           [action ::site/type "Action"]
           [permission ::pass/action action]
           [(contains? actions action)]

           (allowed? permission subject action resource)]

         :rules rules

         :in '[resource actions]}

        resource actions)))

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

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"
   ::site/type "Resource"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"
   ::site/type "Resource"})

(def READ_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/read-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"})

(def WRITE_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/write-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/action-args [{}]})

(def READ_SHARED_ACTION
  {:xt/id "https://example.org/actions/read-shared"
   ::site/type "Action"})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/permissions/alice-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/alice-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action "https://example.org/actions/write-user-dir"})

(def BOB_CAN_READ
  {:xt/id "https://example.org/permissions/bob-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/permissions/alice-shares-file-with-bob"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/read-shared"
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/bob-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/write-user-dir"})

(def WRITE_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/write-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [resource ::site/type "Resource"]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_SHARED_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-shared"]
     [permission ::pass/resource resource]]])



#_((t/join-fixtures [with-xt])
   (fn []
     (submit-and-await!
      [
       ;; Actions
       [::xt/put READ_USER_DIR_ACTION]
       [::xt/put READ_SHARED_ACTION]
       [::xt/put WRITE_USER_DIR_ACTION]

       ;; Actors
       [::xt/put ALICE]
       [::xt/put BOB]
       [::xt/put CARL]

       ;; Resources
       [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
       [::xt/put ALICE_USER_DIR_SHARED_FILE]

       ;; Permissions
       [::xt/put ALICE_CAN_READ]
       [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
       [::xt/put BOB_CAN_READ]
       [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]
       [::xt/put ALICES_SHARES_FILE_WITH_BOB]])

     (allowed-subjects
      (xt/db *xt-node*)
      (:xt/id ALICE_USER_DIR_SHARED_FILE)
      (set (map :xt/id [READ_USER_DIR_ACTION READ_SHARED_ACTION]))
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES)))
     ))

(deftest user-dir-test
  (submit-and-await!
   [
    ;; Actions
    [::xt/put READ_USER_DIR_ACTION]
    [::xt/put READ_SHARED_ACTION]
    [::xt/put WRITE_USER_DIR_ACTION]

    ;; Actors
    [::xt/put ALICE]
    [::xt/put BOB]
    [::xt/put CARL]

    ;; Resources
    [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
    [::xt/put ALICE_USER_DIR_SHARED_FILE]

    ;; Permissions
    [::xt/put ALICE_CAN_READ]
    [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put BOB_CAN_READ]
    [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put ALICES_SHARES_FILE_WITH_BOB]])

  (let [rules (vec (concat WRITE_USER_DIR_RULES READ_USER_DIR_RULES READ_SHARED_RULES))
        db (xt/db *xt-node*)]

    (are [subject actions resource ok?]
        (let [actual (check-permissions db subject actions resource rules)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/private.txt"
      true

      ;; Alice can read the file in her user directory which she has shared with
      ;; Bob.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/shared.txt"
      true

      ;; Bob cannot read Alice's private file.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/private.txt"
      false

      ;; Bob can read the file Alice has shared with him.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-shared"}
      "https://example.org/~alice/shared.txt"
      true

      ;; Alice can put a file to her user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~alice/foo.txt"
      true

      ;; Alice can't put a file to Bob's user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~bob/foo.txt"
      false

      ;; Alice can't put a file outside her user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/index.html"
      false

      ;; Bob can put a file to his user directory
      "https://example.org/people/bob"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~bob/foo.txt"
      true

      ;; Bob can't put a file to Alice's directory
      "https://example.org/people/bob"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~alice/foo.txt"
      false

      ;; Carl cannot put a file to his user directory, as he hasn't been
      ;; granted the write-user-dir action.
      "https://example.org/people/carl"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~carl/foo.txt"
      false)

    (are [subject actions rules expected]
        (is (= expected (allowed-resources db subject actions rules)))

      ;; Alice can see all her files.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{["https://example.org/~alice/shared.txt"]
        ["https://example.org/~alice/private.txt"]}

      ;; Bob can only see the file Alice has shared with him.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{["https://example.org/~alice/shared.txt"]})

    ;; Given a resource and a set of actions, which subjects can access
    ;; and via which actions?

    (are [resource actions rules expected]
        (is (= expected (allowed-subjects db resource actions rules)))

      "https://example.org/~alice/shared.txt"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{{:subject "https://example.org/people/bob",
         :action "https://example.org/actions/read-shared"}
        {:subject "https://example.org/people/alice",
         :action "https://example.org/actions/read-user-dir"}}

      "https://example.org/~alice/private.txt"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{{:subject "https://example.org/people/alice",
         :action "https://example.org/actions/read-user-dir"}})

    ))


;; TODO
;; Next up. Sharing itself. Is Alice even permitted to share her files?
;; read-only, read/write

;; TODO Consent. Alice consents that her PII be used but only for certain
;; purposes (e.g. not marketing).

;; TODO: INTERNAL classification, different security models, see
;; https://en.m.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model

;; TODO: Extend to GraphQL

;; TODO: View restricted info

((t/join-fixtures [with-xt])

 (fn []
   (let [READ_USERNAME_ACTION
         {:xt/id "https://example.org/actions/read-username"
          ::site/type "Action"
          ::pass/pull [::username]}

         READ_SECRETS_ACTION
         {:xt/id "https://example.org/actions/read-secrets"
          ::site/type "Action"
          ::pass/pull [::secret]}

         BOB_CAN_READ_ALICE_USERNAME
         {:xt/id "https://example.org/permissions/bob-can-read-alice-username"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/bob"
          ::pass/action "https://example.org/actions/read-username"
          ::pass/resource "https://example.org/people/alice"}

         BOB_CAN_READ_ALICE_SECRETS
         {:xt/id "https://example.org/permissions/bob-can-read-alice-secrets"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/bob"
          ::pass/action "https://example.org/actions/read-secrets"
          ::pass/resource "https://example.org/people/alice"}

         CARL_CAN_READ_ALICE_USERNAME
         {:xt/id "https://example.org/permissions/carl-can-read-alice-username"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/carl"
          ::pass/action "https://example.org/actions/read-username"
          ::pass/resource "https://example.org/people/alice"}

         RULES
         '[[(allowed? permission subject action resource)
            [permission ::pass/subject subject]
            [action :xt/id "https://example.org/actions/read-username"]
            [permission ::pass/resource resource]]

           [(allowed? permission subject action resource)
            [permission ::pass/subject subject]
            [action :xt/id "https://example.org/actions/read-secrets"]
            [permission ::pass/resource resource]]]

         authorized-pull
         (fn [db subject actions resource rules]
           (mapv
            (fn [[permission]]
              (xt/entity db permission)
              )
            (check-permissions db subject actions resource rules)))
         ]

     (submit-and-await!
      [
       ;; Actors
       [::xt/put (assoc ALICE ::secret "foo")]
       [::xt/put BOB]
       [::xt/put CARL]

       [::xt/put READ_USERNAME_ACTION]
       [::xt/put READ_SECRETS_ACTION]
       [::xt/put BOB_CAN_READ_ALICE_USERNAME]
       [::xt/put BOB_CAN_READ_ALICE_SECRETS]
       [::xt/put CARL_CAN_READ_ALICE_USERNAME]

       ])

     ;; Bob can read Alice's secret
     (let [db (xt/db *xt-node*)]
       (authorized-pull
        db (:xt/id CARL) #{(:xt/id READ_USERNAME_ACTION) (:xt/id READ_SECRETS_ACTION)} (:xt/id ALICE)
        (vec (concat RULES)))))

   ;; ... but Carl cannot

   ))
